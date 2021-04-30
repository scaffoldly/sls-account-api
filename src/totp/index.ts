import * as twofactor from 'node-2fa';
import { accountsTable } from 'src/db';
import { AWS, HttpError } from '@scaffoldly/serverless-util';
import { env } from '../env';
import * as totpTemplate from '../templates/totp.json';
import { STAGE } from 'src/constants';
import * as _ from 'lodash';
import { Totp, VerificationMethod } from 'src/types';

const ses = new AWS.SES();

export const fetchTemplate = async (): Promise<string> => {
  const templateName = `totp-${STAGE}`;
  const source = {
    TemplateName: templateName,
    SubjectPart: totpTemplate.SubjectPart,
    HtmlPart: totpTemplate.HtmlPart,
    TextPart: totpTemplate.TextPart,
  };

  let template: AWS.SES.GetTemplateResponse;
  try {
    template = await ses.getTemplate({ TemplateName: templateName }).promise();
  } catch (e) {
    console.log('Creating template', templateName);
    await ses.createTemplate({ Template: source }).promise();
    template = await ses.getTemplate({ TemplateName: templateName }).promise();
  }

  if (!_.isEqual(template.Template, source)) {
    console.log('Updating template', templateName);
    await ses.updateTemplate({ Template: source }).promise();
  }

  console.log('Using template', template.Template.TemplateName);
  return template.Template.TemplateName;
};

export const sendTotp = async (id: string): Promise<VerificationMethod> => {
  console.log('Fetching TOTP configuration for id:', id);

  let { attrs: totp }: { attrs: Totp } = (await accountsTable.model.get(id, 'totp', {})) || {};

  if (!totp) {
    console.log(`Generating OTP for ${id}`);
    const { secret, uri } = twofactor.generateSecret({ account: id, name: 'TODO: OrgName' });
    // TODO: Encrypt secret/qr/url
    // TODO: Recovery Codes
    ({ attrs: totp } = await accountsTable.model.create(
      { id, sk: 'totp', detail: { secret, uri, verified: false, authenticator: false } },
      { overwrite: false }
    ));
  }

  const { verified, authenticator } = totp.detail;
  console.log(`OTP status for ${id}: verified: ${verified} authenticator: ${authenticator}`);

  if (!verified || !authenticator) {
    //TODO: SMS's
    //TODO: Prob should be a standalone email service
    console.log(`Sending OTP via email to ${id}`);

    const { token } = twofactor.generateToken(totp.detail.secret);

    const result = await ses
      .sendTemplatedEmail({
        Source: `no-reply@${env.env_vars.MAIL_DOMAIN}`,
        Destination: { ToAddresses: [id] },
        Template: await fetchTemplate(),
        TemplateData: JSON.stringify({ Organization: 'TODO: OrgName', OTP: token }),
      })
      .promise();

    console.log('OTP Code sent via Email:', result);

    return 'EMAIL';
  }

  console.log('Nothing to send, Authenticator is enabled');
  return 'AUTHENTICATOR';
};

export const verifyTotp = async (email: string, code: string): Promise<boolean> => {
  console.log('Fetching TOTP configuration for id:', email);
  const { attrs: totp }: { attrs: Totp } = (await accountsTable.model.get(email, 'totp', {})) || {};

  if (!totp) {
    throw new HttpError(403, 'TOTP is not configured');
  }

  const { secret, authenticator } = totp.detail;
  if (!secret) {
    throw new HttpError(403, 'Missing OTP Secret');
  }

  const verification = twofactor.verifyToken(secret, code, authenticator ? 4 : 10);
  console.log(`Verification result for ${email} was ${JSON.stringify(verification)}`);

  if (!verification) {
    throw new HttpError(403, 'Invalid code or the code has expired');
  }

  console.log('Email/OTP has been successfully verified');
  totp.detail.verified = true;
  await accountsTable.model.update(totp, {});

  return true;
};

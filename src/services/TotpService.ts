import { HttpError, AWS } from '@scaffoldly/serverless-util';
import * as twofactor from 'node-2fa';
import { env } from '../env';
import { VerificationMethod } from '../models/interfaces';
import { TotpModel } from '../models/TotpModel';

import TemplateService from './TemplateService';

export default class TotpService {
  ses: AWS.SES;

  totpModel: TotpModel;

  templateService: TemplateService;

  constructor() {
    this.ses = new AWS.SES();
    this.totpModel = new TotpModel();
    this.templateService = new TemplateService();
  }

  sendTotp = async (id: string, email: string): Promise<VerificationMethod> => {
    console.log('Fetching TOTP configuration for id:', id);

    let totp = await this.totpModel.model.get(id, 'totp');

    if (!totp) {
      console.log(`Generating OTP for ${id}`);
      const { secret } = twofactor.generateSecret({
        account: email,
        name: env.APPLICATION_FRIENDLY_NAME,
      });
      // TODO: Encrypt secret/qr/url
      // TODO: Recovery Codes
      totp = await this.totpModel.model.create(
        {
          id,
          sk: 'totp',
          detail: { secret, verified: false, authenticator: false },
        },
        { overwrite: false },
      );
    }

    const { verified, authenticator } = totp.attrs.detail;
    console.log(`OTP status for ${id}: verified: ${verified} authenticator: ${authenticator}`);

    if (!verified || !authenticator) {
      // TODO: SMS's
      // TODO: Prob should be a standalone email service
      console.log(`Sending OTP via email to ${email}`);

      const { token } = twofactor.generateToken(totp.attrs.detail.secret) || {};

      const result = await this.ses
        .sendTemplatedEmail({
          Source: `no-reply@${env.MAIL_DOMAIN}`,
          Destination: { ToAddresses: [email] },
          Template: await this.templateService.fetchTemplate('totp'),
          TemplateData: JSON.stringify({
            Organization: env.APPLICATION_FRIENDLY_NAME,
            OTP: token,
          }),
        })
        .promise();

      console.log('OTP Code sent via Email:', result);

      return 'EMAIL';
    }

    console.log('Nothing to send, Authenticator is enabled');
    return 'AUTHENTICATOR';
  };

  verifyTotp = async (id: string, email: string, code: string): Promise<boolean> => {
    console.log('Fetching TOTP configuration for id:', email);
    const totp = await this.totpModel.model.get(id, 'totp');

    if (!totp) {
      throw new HttpError(403, 'TOTP is not configured');
    }

    const { secret, authenticator } = totp.attrs.detail;
    if (!secret) {
      throw new HttpError(403, 'Missing OTP Secret');
    }

    const verification = twofactor.verifyToken(secret, code, authenticator ? 4 : 10);
    console.log(`Verification result for ${email} was ${JSON.stringify(verification)}`);

    if (!verification) {
      throw new HttpError(403, 'Invalid code or the code has expired');
    }

    console.log('Email/OTP has been successfully verified');
    totp.attrs.detail.verified = true;
    await this.totpModel.model.update(totp.attrs);

    return true;
  };
}

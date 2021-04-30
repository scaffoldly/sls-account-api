import { handleSuccess, AWS, handleError } from '@scaffoldly/serverless-util';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { ProviderResponse } from 'src/types';
import { env } from '../../../env';

const ses = new AWS.SES();

const isVerified = async (domain: string) => {
  const verificationAttributes = await ses
    .getIdentityVerificationAttributes({ Identities: [domain] })
    .promise();
  const { VerificationAttributes } = verificationAttributes;
  if (!VerificationAttributes) {
    console.warn('Unable to find SES domain verification attributes', verificationAttributes);
    return false;
  }

  const attributes = VerificationAttributes[domain];
  if (!attributes) {
    console.warn(
      `Unable to find SES domain verification attributes for domain ${domain}`,
      verificationAttributes
    );
    return false;
  }

  if (attributes.VerificationStatus !== 'Success') {
    console.warn(`SES domain ${domain} is not verified`, attributes);
    return false;
  }

  return true;
};

export const getV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const response: ProviderResponse = {
      APPLE: env.env_vars.APPLE_CLIENT_ID
        ? { name: 'Apple', clientId: env.env_vars.APPLE_CLIENT_ID }
        : undefined,
      GOOGLE: env.env_vars.GOOGLE_CLIENT_ID
        ? { name: 'Google', clientId: env.env_vars.GOOGLE_CLIENT_ID }
        : undefined,
      EMAIL: (await isVerified(env.env_vars.MAIL_DOMAIN))
        ? { name: 'Email', clientId: env.env_vars.MAIL_DOMAIN }
        : undefined,
    };

    return handleSuccess(event, response);
  } catch (e) {
    throw handleError(event, e);
  }
};

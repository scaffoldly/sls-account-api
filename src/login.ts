import { HttpError, optionalParameters, requiredParameters } from '@scaffoldly/serverless-util';
import * as Google from 'google-auth-library';
import * as envVars from '../.scaffoldly/env-vars.json';
import { sendTotp, verifyTotp } from './totp';
import { LoginDetail, VerificationResultBase } from './types';

const verifyGoogleToken = async (token: string): Promise<VerificationResultBase> => {
  const client = new Google.OAuth2Client({ clientId: envVars['GOOGLE_CLIENT_ID'] });

  let result: Google.LoginTicket;
  try {
    result = await client.verifyIdToken({ idToken: token });
  } catch (e) {
    throw new HttpError(401, 'Unauthorized', e);
  }

  if (!result) {
    throw new HttpError(500, 'Verification result was not set');
  }

  const payload = result.getPayload();

  if (!payload) {
    throw new HttpError(500, 'Verification payload was not set');
  }

  const { sub } = payload;

  if (!sub) {
    throw new HttpError(500, 'Verification sub was not set');
  }

  return { verified: true, verificationMethod: 'NONE' };
};

const verifyEmail = async (email: string, code: string): Promise<VerificationResultBase> => {
  if (code) {
    const verified = await verifyTotp(email, code);
    return { verified, verificationMethod: 'NONE' };
  }

  const verificationMethod = await sendTotp(email);
  return { verified: false, verificationMethod };
};

export const verifyLogin = async (body: string): Promise<LoginDetail> => {
  const { provider } = requiredParameters(body, ['provider']);
  switch (provider) {
    case 'GOOGLE': {
      const params = requiredParameters(body, ['id', 'idToken', 'authToken', 'email', 'name']);
      const optParams = optionalParameters(body, ['photoUrl']);
      const result = await verifyGoogleToken(params.idToken);
      return {
        ...result,
        id: params.email,
        provider,
        payload: { ...params, ...optParams },
      };
    }
    case 'EMAIL': {
      const params = requiredParameters(body, ['email']);
      const optParams = optionalParameters(body, ['code']);
      const result = await verifyEmail(params.email, optParams.code);
      return {
        ...result,
        id: params.email,
        provider,
        payload: { ...params },
      };
    }
    default: {
      throw new HttpError(401, `Unknown provider: ${provider}`);
    }
  }
};

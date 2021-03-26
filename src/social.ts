import { HttpError } from '@scaffoldly/serverless-util';
import * as Google from 'google-auth-library';
import { GOOGLE_OAUTH_CLIENT_ID } from './constants';

const verifyGoogleToken = async (token) => {
  const client = new Google.OAuth2Client({ clientId: GOOGLE_OAUTH_CLIENT_ID });

  const result = await client.verifyIdToken({ idToken: token });

  if (!result) {
    return false;
  }

  const payload = result.getPayload();

  if (!payload) {
    return false;
  }

  const { sub } = payload;

  if (!sub) {
    return false;
  }

  return true;
};

export const verifySocialToken = async (provider, token) => {
  let verified = false;
  switch (provider) {
    case 'GOOGLE': {
      verified = await verifyGoogleToken(token);
      break;
    }
    default: {
      console.error(`Unknown provider ${provider}`);
      break;
    }
  }

  if (!verified) {
    throw new HttpError(401, 'Invalid token');
  }
};

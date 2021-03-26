export const { SERVICE_NAME, STAGE, DOMAIN } = process.env;
export const { GOOGLE_OAUTH_CLIENT_ID } = process.env;
export const { JWT_REFRESH_TOKEN_MAX_AGE } = process.env;
export const ACCOUNTS_TABLE = 'accounts';

export const REFRESH_COOKIE_PREFIX = '__Secure-sly_jrt_';

export const SENSITIVE_KEYS = [
  'password',
  'key',
  'x-api-key',
  'api-key',
  'token',
  'secret',
  'authtoken',
  'idtoken',
];
export const AUTH_PREFIXES = ['Bearer', 'jwt'];

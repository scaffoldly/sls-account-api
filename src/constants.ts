export const { SERVICE_NAME, STAGE } = process.env;
export const { JWT_REFRESH_TOKEN_EXPIRATION_SEC = '31540000', JWT_TOKEN_EXPIRATION_SEC = '3600' } =
  process.env;

export const TABLE_SUFFIX = '';

export const REFRESH_COOKIE_PREFIX = '__Secure-sly_jrt_';

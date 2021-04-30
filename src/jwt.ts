import { GetSecret, SetSecret } from '@scaffoldly/serverless-util';
import axios from 'axios';
import { Buffer } from 'buffer';
import * as moment from 'moment';
import { v4 as uuidv4 } from 'uuid';
import { AUTH_PREFIXES, JWT_REFRESH_TOKEN_MAX_AGE, REFRESH_COOKIE_PREFIX } from './constants';
import { accountsTable } from './db';
import { env } from './env';

const JWKS_SECRET_NAME = 'jwks';

import { JWT, JWK, JWKS, JWKECKey } from 'jose';
import {
  DecodedJwtPayload,
  GeneratedKeys,
  JwtPayload,
  Login,
  Refresh,
  TokenResponse,
  VerifyTokenResponse,
} from './types';
import { APIGatewayAuthorizerEvent, APIGatewayProxyEvent } from 'aws-lambda';
import { cleanseObject } from './util';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const Cookies = require('cookies');

const jwksCache = {};

const generateAudience = (id: string) => {
  return `urn:auth:${env.env_vars.SERVERLESS_API_DOMAIN.split('.').reverse().join('.')}:${id}`;
};

export const generateKeys = (issuer: string): GeneratedKeys => {
  const kid = uuidv4();
  const key = JWK.generateSync('EC', 'P-256', { use: 'sig', kid }, true);
  console.log(`Generated a new key with kid: ${kid}`);

  return {
    issuer,
    publicKey: {
      pem: key.toPEM(false),
      jwk: key.toJWK(false),
    },
    privateKey: {
      pem: key.toPEM(true),
      jwk: key.toJWK(true),
    },
  };
};

export const getOrCreateKeys = async (): Promise<GeneratedKeys> => {
  let keys = await GetSecret(JWKS_SECRET_NAME);

  if (!keys) {
    const generatedKeys = generateKeys(env.env_vars.SERVERLESS_API_DOMAIN);

    await SetSecret(JWKS_SECRET_NAME, JSON.stringify(generatedKeys), true);
    keys = await GetSecret(JWKS_SECRET_NAME);
    if (!keys) {
      throw new Error('Unknown issue generating/storing JWKS');
    }
  }

  return JSON.parse(Buffer.from(keys, 'base64').toString('utf8'));
};

export const getPublicKey = async (): Promise<JWKECKey> => {
  const keys = await getOrCreateKeys();
  return keys.publicKey.jwk;
};

export const createEmptyToken = (login: Login, event: APIGatewayProxyEvent): TokenResponse => {
  const { headers } = event;
  let { path } = event;
  const { Host } = headers;
  const ssl = headers['X-Forwarded-Proto'] === 'https';

  path = path.replace(/\/refresh$/gim, '');

  const obj: JwtPayload = {
    ...cleanseObject(login.detail.payload),
    id: login.id,
    sk: login.sk,
    refreshUrl: `${ssl ? 'https' : 'http'}://${Host}${path}/refresh`,
    verifyUrl: `${ssl ? 'https' : 'http'}://${Host}${path}/verify`,
    certsUrl: `${ssl ? 'https' : 'http'}://${Host}${path}/certs`,
  };

  return {
    ...login.detail,
    payload: obj,
    token: null,
  };
};

export const createToken = async (
  login: Login,
  event: APIGatewayProxyEvent
): Promise<TokenResponse> => {
  const response = createEmptyToken(login, event);

  const keys = await getOrCreateKeys();
  const key = JWK.asKey(keys.privateKey.jwk);
  const token = JWT.sign(response.payload, key, {
    audience: generateAudience(login.id),
    expiresIn: '60 minute',
    header: {
      typ: 'JWT',
    },
    subject: login.id,
    issuer: response.payload.certsUrl,
  });

  response.token = token;

  return response;
};

export const createRefreshToken = async (
  id: string,
  sk: string,
  event: APIGatewayProxyEvent,
  token = uuidv4()
): Promise<Refresh> => {
  const { headers } = event;
  const { Host } = headers;

  const cookie = new Cookies.Cookie(`${REFRESH_COOKIE_PREFIX}${sk}`, token, {
    domain: Host,
    maxAge: parseInt(JWT_REFRESH_TOKEN_MAX_AGE, 10),
    overwrite: true,
    path: '/',
    httpOnly: true,
    sameSite: 'none',
    secure: true,
  });

  console.log('New cookie', cookie);

  const { attrs: refresh }: { attrs: Refresh } = await accountsTable.model.create(
    {
      id,
      sk: `jwt_refresh_${sk}`,
      detail: {
        sk,
        token,
        expires: moment().add(JWT_REFRESH_TOKEN_MAX_AGE, 'millisecond').unix(),
        header: cookie.toHeader(),
      },
    },
    { overwrite: true }
  );

  return refresh;
};

const extractToken = (authorization: string): string => {
  if (!authorization) {
    throw new Error('Missing authorization header');
  }

  let token = authorization;

  const parts = token.split(' ');
  if (parts.length > 2) {
    throw new Error('Malformed authorization header');
  }

  if (parts.length === 2) {
    const prefix = parts[0];
    if (AUTH_PREFIXES.indexOf(prefix) === -1) {
      throw new Error(`Invalid token type: ${prefix}`);
    }
    [, token] = parts;
  }

  return token;
};

export const fetchJwks = async (url: string): Promise<JWKS.KeyStore> => {
  if (!url) {
    throw new Error('URL is required');
  }

  if (
    jwksCache[url] &&
    jwksCache[url].keys &&
    jwksCache[url].expires &&
    moment(jwksCache[url].expires).isAfter(moment())
  ) {
    return jwksCache[url].keys;
  }

  const response = await axios.get(url);

  if (!response || !response.data) {
    throw new Error(`Unable to get keys from url: ${url}`);
  }

  const { data } = response;

  const keys = JWKS.asKeyStore(data);

  // TODO Use Cache Control header
  jwksCache[url] = {
    expires: moment().add(6, 'hour'),
    keys,
  };

  return keys;
};

const extractAuthorization = (event) => {
  if (!event) {
    console.warn('Missing event');
    return null;
  }

  if (event.authorizationToken) {
    return event.authorizationToken;
  }

  const { headers } = event;

  if (!headers) {
    console.warn('Missing headers');
    return null;
  }

  const { Authorization } = headers;
  if (Authorization) {
    return Authorization;
  }

  const { authorization } = headers;
  if (authorization) {
    return authorization;
  }

  console.warn('Authorization token not found in event');

  return null;
};

const extractRefreshCookie = (event: APIGatewayProxyEvent, sk: string) => {
  const cookie = {
    name: `${REFRESH_COOKIE_PREFIX}${sk}`,
    value: null,
  };

  if (!event) {
    console.warn('Missing event');
    return cookie;
  }

  const { headers } = event;
  if (!headers) {
    console.warn('Missing headers');
    return cookie;
  }

  const { Cookie } = headers;
  if (!Cookie) {
    console.warn('Missing Cookie header');
    return cookie;
  }

  const cookies = Cookie.split(';');
  if (!cookies || cookies.length === 0) {
    console.warn('No cookies');
    return cookie;
  }

  return cookies.reduce((acc, item) => {
    if (acc.value) {
      return acc;
    }

    const [name, value] = item.trim().split('=');
    if (!name || !value) {
      console.warn(`Missing name or value in ${item}`);
      return acc;
    }

    if (name === acc.name) {
      acc.value = value;
    }

    return acc;
  }, cookie);
};

export const verifyJwt = async (jwt: string): Promise<DecodedJwtPayload> => {
  const decoded = JWT.decode(jwt) as DecodedJwtPayload;
  if (!decoded) {
    throw new Error('Unable to decode token');
  }

  const { aud: principal, iss } = decoded;
  if (!principal) {
    throw new Error('Missing principal in decoded token');
  }

  if (!iss) {
    throw new Error('Missing issuer in decoded token');
  }

  const keys = await getOrCreateKeys();
  const { issuer } = keys;
  if (!issuer) {
    throw new Error(`Unable to find secret: ${JWKS_SECRET_NAME}`);
  }

  const issuerUrl = new URL(iss);
  if (issuerUrl.hostname.indexOf(issuer) === -1) {
    throw new Error(
      `Issuer mismatch. Got: ${decoded.iss}; Expected hostname to contain: ${issuer}`
    );
  }

  const jwks = await fetchJwks(decoded.iss);
  const verified = JWT.verify(jwt, jwks, {});

  if (!verified) {
    throw new Error('Unable to verify token');
  }

  if (verified instanceof Error) {
    throw verified;
  }

  return verified as DecodedJwtPayload;
};

export const verifyToken = async (
  event: APIGatewayAuthorizerEvent
): Promise<VerifyTokenResponse> => {
  const response = {
    principal: undefined,
    authorized: false,
    payload: undefined,
    error: undefined,
  };

  const authorization = extractAuthorization(event);

  if (!authorization) {
    response.error = new Error("Missing Authorization header or 'authorization' query parameter");
    return response;
  }

  let token: string;
  try {
    token = extractToken(authorization);
  } catch (e) {
    response.error = e;
    return response;
  }

  let payload: DecodedJwtPayload;
  try {
    payload = await verifyJwt(token);
  } catch (e) {
    response.error = e;
    return response;
  }

  response.principal = payload.aud;
  response.authorized = true;
  response.payload = payload;

  return response;
};

export const fetchRefreshRecord = async (event: APIGatewayProxyEvent): Promise<Refresh> => {
  if (!event) {
    console.warn('Unable to refresh: event is empty');
    return null;
  }

  const authorization = extractAuthorization(event);
  if (!authorization) {
    console.warn('Missing authorization');
    return null;
  }

  const token = extractToken(authorization);
  if (!token) {
    console.warn('Missing token');
    return null;
  }

  const decoded = JWT.decode(token) as DecodedJwtPayload;
  if (!decoded) {
    console.warn('Unable to decode token');
    return null;
  }

  if (!decoded.id || !decoded.sk) {
    console.warn('Missing id or sk in token');
    return null;
  }

  // Lookup refresh token using decoded.id and 'jwt_refresh"
  const { attrs: record }: { attrs: Refresh } =
    (await accountsTable.model.get(decoded.id, `jwt_refresh_${decoded.sk}`, {})) || {};

  if (!record) {
    console.warn(`Unable to find refresh record for ${decoded.id} ${decoded.sk}`);
    return null;
  }

  // Parse cookie from event header
  const cookie = extractRefreshCookie(event, decoded.sk);
  if (!cookie.value) {
    console.warn(`Unable to find cookie with name ${cookie.name}`);
    return null;
  }

  // Compare sly_jrt and decoded.sk value with result from DB
  if (record.detail.token !== cookie.value) {
    console.warn(
      `Token mismatch. Expected ${record.detail.token}, got ${cookie.value} from cookie ${cookie.name}`
    );
    return null;
  }

  // TODO: Ensure social auth credentials are still good

  return record;
};

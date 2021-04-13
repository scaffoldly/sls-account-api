import { GetSecret, SetSecret } from '@scaffoldly/serverless-util';
import axios from 'axios';
import { Buffer } from 'buffer';
import * as moment from 'moment';
import { v4 as uuidv4 } from 'uuid';
import { AUTH_PREFIXES, JWT_REFRESH_TOKEN_MAX_AGE, REFRESH_COOKIE_PREFIX } from './constants';
import { accountsTable } from './db';

const JWT_PRIVATE_KEY_SECRET_NAME = 'jwtPrivateKey';
const JWT_PUBLIC_KEY_SECRET_NAME = 'jwtPublicKey';
const JWT_ISSUER_SECRET_NAME = 'jwtIssuer';

import { JWT, JWK, JWKS, JWKECKey } from 'jose';
import {
  CleansedObject,
  DecodedLoginToken,
  GeneratedKeys,
  RefreshTokenResponse,
  RefreshTokenRow,
  TokenResponse,
  VerifyTokenResponse,
} from './types';
import { APIGatewayAuthorizerEvent, APIGatewayProxyEvent } from 'aws-lambda';
// const {
//   JWT: { sign, decode, verify },
//   JWK: { generateSync, asKey },
//   JWKS: { asKeyStore },
//   // eslint-disable-next-line @typescript-eslint/no-var-requires
// } = require('jose');

// eslint-disable-next-line @typescript-eslint/no-var-requires
const Cookies = require('cookies');

const jwksCache = {};

const generateAudience = (host: string, id: string) => {
  return `urn:auth:${host.split('.').reverse().join('.')}:${id}`;
};

export const generateKeys = (): GeneratedKeys => {
  const kid = uuidv4();
  const key = JWK.generateSync('EC', 'P-256', { use: 'sig', kid }, true);
  console.log(`Generated a new key with kid: ${kid}`);

  return {
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

export const getOrCreateKeys = async (issuer: string): Promise<JWKECKey> => {
  let privateKey = await GetSecret(JWT_PRIVATE_KEY_SECRET_NAME);

  if (!privateKey) {
    const keys = generateKeys();

    await SetSecret(JWT_PUBLIC_KEY_SECRET_NAME, JSON.stringify(keys.publicKey.jwk), true);
    await SetSecret(JWT_ISSUER_SECRET_NAME, issuer);

    privateKey = await SetSecret(
      JWT_PRIVATE_KEY_SECRET_NAME,
      JSON.stringify(keys.privateKey.jwk),
      true
    );
  }

  return JSON.parse(Buffer.from(privateKey, 'base64').toString('utf8'));
};

export const getPublicKey = async (issuer: string): Promise<JWKECKey> => {
  let publicKey = await GetSecret(JWT_PUBLIC_KEY_SECRET_NAME);
  if (!publicKey) {
    await getOrCreateKeys(issuer);
    publicKey = await GetSecret(JWT_PUBLIC_KEY_SECRET_NAME);
  }

  return JSON.parse(Buffer.from(publicKey, 'base64').toString('utf8'));
};

export const createToken = async (
  id: string,
  payload: CleansedObject,
  event: APIGatewayProxyEvent
): Promise<TokenResponse> => {
  const { path, headers } = event;
  const { Host } = headers;
  const ssl = headers['X-Forwarded-Proto'] === 'https';

  const obj = {
    ...payload,
    refreshUrl: `${ssl ? 'https' : 'http'}://${Host}${path}/refresh`,
    verifyUrl: `${ssl ? 'https' : 'http'}://${Host}${path}/verify`,
  };

  const privateKey = await getOrCreateKeys(Host);
  const key = JWK.asKey(privateKey);
  return {
    payload: obj,
    token: JWT.sign(obj, key, {
      audience: generateAudience(Host, id),
      expiresIn: '60 minute',
      header: {
        typ: 'JWT',
      },
      subject: id,
      issuer: `${ssl ? 'https' : 'http'}://${Host}${path}/certs`,
    }),
  };
};

export const createRefreshToken = async (
  id: string,
  sk: string,
  event: APIGatewayProxyEvent,
  token = uuidv4()
): Promise<RefreshTokenResponse> => {
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

  const row = await accountsTable.model.create(
    {
      id,
      sk: `jwt_refresh_${sk}`,
      name: sk,
      token,
      expires: moment().add(JWT_REFRESH_TOKEN_MAX_AGE, 'millisecond').unix(),
      header: cookie.toHeader(),
    } as RefreshTokenRow,
    { overwrite: true }
  );

  return {
    token: row.get('token'),
    header: row.get('header'),
  };
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

const extractRefreshCookie = (event, sk) => {
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

export const verifyJwt = async (jwt: string): Promise<DecodedLoginToken> => {
  const decoded = JWT.decode(jwt) as DecodedLoginToken;
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

  const issuer = await GetSecret(JWT_ISSUER_SECRET_NAME);
  if (!issuer) {
    throw new Error(`Unable to find secret: ${JWT_ISSUER_SECRET_NAME}`);
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

  return verified as DecodedLoginToken;
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

  let payload: DecodedLoginToken;
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

export const fetchRefreshRecord = async (event: APIGatewayProxyEvent): Promise<RefreshTokenRow> => {
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

  const decoded = JWT.decode(token) as DecodedLoginToken;
  if (!decoded) {
    console.warn('Unable to decode token');
    return null;
  }

  if (!decoded.id || !decoded.sk) {
    console.warn('Missing id or sk in token');
    return null;
  }

  // Lookup refresh token using decoded.id and 'jwt_refresh"
  const record = await accountsTable.model.get(decoded.id, `jwt_refresh_${decoded.sk}`, {});
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
  if (record.get('token') !== cookie.value) {
    console.warn(
      `Token mismatch. Expected ${record.get('token')}, got ${cookie.value} from cookie ${
        cookie.name
      }`
    );
    return null;
  }

  // TODO: Ensure google auth credentials are still good
  return record.attrs;
};

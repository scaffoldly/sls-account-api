import {
  DecodedJwtPayload,
  extractToken,
  generateAudience,
  GetSecret,
  HttpRequest,
  JwtPayload,
  SetSecret,
  verifyAudience,
} from '@scaffoldly/serverless-util';
import { v4 as uuidv4 } from 'uuid';
import { JWT, JWK, JWKECKey, JWKS } from 'jose';
import Cookies from 'cookies';
import moment, { Moment } from 'moment';
import axios from 'axios';
import { ulid } from 'ulid';
import { TokenResponse } from '../interfaces/responses';
import { env } from '../env';
import { GeneratedKeys, Jwk } from '../interfaces/Jwt';
import { JWT_REFRESH_TOKEN_MAX_AGE, REFRESH_COOKIE_PREFIX } from '../constants';
import { RefreshModel } from '../models/RefreshModel';
import { Login, Refresh } from '../models/interfaces';

const JWKS_SECRET_NAME = 'jwks';
const DOMAIN = env.SERVERLESS_API_DOMAIN;

const jwksCache: { [url: string]: { keys: JWKS.KeyStore; expires: Moment } } = {};

export default class JwtService {
  refreshModel: RefreshModel;

  domain: string;

  constructor() {
    this.refreshModel = new RefreshModel();
    this.domain = DOMAIN;
  }

  generateAudience = (id: string): string => {
    return generateAudience(this.domain, id);
  };

  verifyAudience = (aud: string): boolean => {
    return verifyAudience(this.domain, aud);
  };

  getPublicKey = async (): Promise<Jwk> => {
    const keys = await this.getOrCreateKeys();
    return keys.publicKey.jwk;
  };

  createEmptyToken = (
    login: Login,
    request: HttpRequest,
    path: string,
    sessionId = ulid(),
  ): TokenResponse => {
    const { headers } = request;
    const { host } = headers;
    const ssl = headers['x-forwarded-proto'] === 'https';

    const obj: JwtPayload = {
      ...login.detail.request,
      id: login.id,
      sk: login.sk,
      refreshUrl: `${ssl ? 'https' : 'http'}://${host}/${env.SERVICE_NAME}${path}/refresh`,
      authorizeUrl: `${ssl ? 'https' : 'http'}://${host}/${env.SERVICE_NAME}${path}/authorize`,
      certsUrl: `${ssl ? 'https' : 'http'}://${host}/${env.SERVICE_NAME}${path}/certs`,
      sessionId,
    };

    return {
      ...login.detail,
      payload: obj,
      token: null,
    };
  };

  private getOrCreateKeys = async (): Promise<GeneratedKeys> => {
    let keys = await GetSecret(JWKS_SECRET_NAME);

    if (!keys) {
      const generatedKeys = this.generateKeys(env.SERVERLESS_API_DOMAIN);

      await SetSecret(JWKS_SECRET_NAME, JSON.stringify(generatedKeys), true);
      keys = await GetSecret(JWKS_SECRET_NAME);
      if (!keys) {
        throw new Error('Unknown issue generating/storing JWKS');
      }
    }

    return JSON.parse(Buffer.from(keys, 'base64').toString('utf8'));
  };

  createToken = async (
    login: Login,
    request: HttpRequest,
    path: string,
    sessionId = ulid(),
  ): Promise<TokenResponse> => {
    const response = this.createEmptyToken(login, request, path, sessionId);

    const keys = await this.getOrCreateKeys();
    const key = JWK.asKey(keys.privateKey.jwk as JWKECKey);
    const token = JWT.sign(response.payload, key, {
      audience: this.generateAudience(login.id),
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

  createRefreshToken = async (
    login: Login,
    request: HttpRequest,
    sessionId: string,
    token = uuidv4(),
  ): Promise<Refresh> => {
    const { headers } = request;
    const { Host } = headers;

    const cookie = new Cookies.Cookie(`${REFRESH_COOKIE_PREFIX}${login.sk}`, token, {
      domain: Host as string,
      maxAge: parseInt(JWT_REFRESH_TOKEN_MAX_AGE, 10),
      overwrite: true,
      path: '/',
      httpOnly: true,
      sameSite: 'none',
      secure: true,
    });

    const refreshRow = await this.refreshModel.model.create(
      {
        id: login.id,
        sk: `jwt_refresh_${login.sk}_${sessionId}`,
        detail: {
          sk: login.sk,
          token,
          expires: moment().add(JWT_REFRESH_TOKEN_MAX_AGE, 'millisecond').unix(),
          header: cookie.toHeader(),
          sessionId,
        },
      },
      { overwrite: true },
    );

    return refreshRow.attrs;
  };

  fetchRefreshRow = async (
    authorization: string,
    request: HttpRequest,
  ): Promise<Refresh | null> => {
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

    const sk = `jwt_refresh_${decoded.sk}_${decoded.sessionId}`;

    const refreshRow = await this.refreshModel.model.get(decoded.id, sk);

    if (!refreshRow) {
      console.warn(`Unable to find refresh record for id: ${decoded.id} sk: ${sk}`);
      return null;
    }

    // Parse cookie from event header
    const cookie = this.extractRefreshCookie(request, decoded.sk);
    if (!cookie.value) {
      console.warn(`Unable to find cookie with name ${cookie.name}`);
      return null;
    }

    // Compare sly_jrt and decoded.sk value with result from DB
    if (refreshRow.attrs.detail.token !== cookie.value) {
      console.warn(
        `Token mismatch. Expected ${refreshRow.attrs.detail.token}, got ${cookie.value} from cookie ${cookie.name}`,
      );
      return null;
    }

    // TODO: Ensure social auth credentials are still good

    return refreshRow.attrs;
  };

  verifyJwt = async (jwt: string): Promise<DecodedJwtPayload> => {
    const decoded = JWT.decode(jwt) as DecodedJwtPayload;
    if (!decoded) {
      throw new Error('Unable to decode token');
    }

    const { aud, iss } = decoded;
    if (!aud) {
      throw new Error('Missing audience in decoded token');
    }

    if (!this.verifyAudience(aud)) {
      throw new Error('Invalid audience');
    }

    if (!iss) {
      throw new Error('Missing issuer in decoded token');
    }

    const keys = await this.getOrCreateKeys();
    const { issuer } = keys;
    if (!issuer) {
      throw new Error(`Unable to find secret: ${JWKS_SECRET_NAME}`);
    }

    const issuerUrl = new URL(iss);
    if (issuerUrl.hostname.indexOf(issuer) === -1) {
      throw new Error(
        `Issuer mismatch. Got: ${decoded.iss}; Expected hostname to contain: ${issuer}`,
      );
    }

    const jwks = await this.fetchJwks(decoded.iss);
    const verified = JWT.verify(jwt, jwks, {});

    if (!verified) {
      throw new Error('Unable to verify token');
    }

    if (verified instanceof Error) {
      throw verified;
    }

    return verified as DecodedJwtPayload;
  };

  private fetchJwks = async (url: string): Promise<JWKS.KeyStore> => {
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

  private generateKeys = (issuer: string): GeneratedKeys => {
    const kid = uuidv4();
    const key = JWK.generateSync('EC', 'P-256', { use: 'sig', kid }, true);
    console.log(`Generated a new key with kid: ${kid}`);

    return {
      issuer,
      publicKey: {
        pem: key.toPEM(false),
        jwk: key.toJWK(false) as Jwk,
      },
      privateKey: {
        pem: key.toPEM(true),
        jwk: key.toJWK(true) as Jwk,
      },
    };
  };

  private extractRefreshCookie = (request: HttpRequest, sk: string) => {
    const refreshCookie = {
      name: `${REFRESH_COOKIE_PREFIX}${sk}`,
      value: null as string | null,
    };

    if (!request) {
      console.warn('Missing request');
      return refreshCookie;
    }

    const { headers } = request;
    if (!headers) {
      console.warn('Missing headers');
      return refreshCookie;
    }

    const { cookie } = headers as Record<string, string>;
    if (!cookie) {
      console.warn('Missing Cookie header');
      return refreshCookie;
    }

    const cookies = cookie.split(';');
    if (!cookies || cookies.length === 0) {
      console.warn('No cookies');
      return refreshCookie;
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
    }, refreshCookie);
  };
}

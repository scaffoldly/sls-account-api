import { JWKECKey } from 'jose';

export interface PemJwk {
  pem: string;
  jwk: JWKECKey;
}

export interface GeneratedKeys {
  publicKey: PemJwk;
  privateKey: PemJwk;
}

export interface TokenResponse {
  payload: unknown;
  token: string;
}

export interface RowBase {
  id: string;
  sk: string;
}

export interface LoginTokenBase {
  id: string;
  email: string;
  name: string;
  provider: string;
  photoUrl?: string;
}

export interface LoginTokenRequest extends LoginTokenBase {
  idToken: string;
  authToken: string;
}

export interface LoginTokenRowBase extends LoginTokenBase, RowBase {
  baseUrl: string;
  createdAt: string;
}

export interface LoginTokenRow extends LoginTokenRowBase, LoginTokenRequest {}

export interface RefreshTokenResponse {
  token: string;
  header: string;
}

export interface RefreshTokenRow extends RowBase, RefreshTokenResponse {
  name: string;
  expires: number;
}

export type CleansedObject = { [key: string]: string | number | boolean };

export interface DecodedLoginToken extends LoginTokenBase, LoginTokenRowBase, CleansedObject {
  refreshUrl: string;
  sub: string;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
}

export interface VerifyTokenResponse {
  principal?: string;
  authorized: boolean;
  payload?: DecodedLoginToken;
  error?: Error;
}

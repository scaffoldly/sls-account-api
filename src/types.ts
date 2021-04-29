import { JWKECKey } from 'jose';

export interface PemJwk {
  pem: string;
  jwk: JWKECKey;
}

export interface GeneratedKeys {
  issuer: string;
  publicKey: PemJwk;
  privateKey: PemJwk;
}

export type CleansedObject = { [key: string]: string | number | boolean };

export interface JwtPayload extends CleansedObject {
  id: string;
  sk: string;
  refreshUrl: string;
  verifyUrl: string;
  certsUrl: string;
}

export interface DecodedJwtPayload extends JwtPayload {
  sub: string;
  aud: string;
  iss: string;
  iat: number;
  exp: number;
}

export interface VerifyTokenResponse {
  principal?: string;
  authorized: boolean;
  payload?: DecodedJwtPayload;
  error?: Error;
}

export type Provider = 'GOOGLE' | 'APPLE' | 'EMAIL';

export interface ProviderDetail {
  name: string;
  clientId: string | undefined;
}

export type ProviderResponse = {
  [provider in Provider]: ProviderDetail | null;
};

export interface Row<T> {
  id: string;
  sk: string;
  detail: T;
}

export type VerificationMethod = 'EMAIL' | 'AUTHENTICATOR' | 'NONE';

export interface VerificationResultBase {
  verified: boolean;
  verificationMethod: VerificationMethod;
}

export interface LoginDetail extends VerificationResultBase {
  id: string;
  provider: Provider;
  payload?: { [key: string]: unknown };
}

export type Login = Row<LoginDetail>;

export interface TokenResponse extends LoginDetail {
  payload: JwtPayload;
  token: string;
}

export interface TotpDetail {
  secret: string;
  verified: boolean;
  authenticator: boolean;
}

export type Totp = Row<TotpDetail>;

export interface RefreshDetail {
  sk: string;
  token: string;
  expires: number;
  header: string;
}

export type Refresh = Row<RefreshDetail>;

export interface PrimaryAccountDetail {
  name?: string;
  email?: string;
  company?: string;
}

export type PrimaryAccount = Row<PrimaryAccountDetail>;

import { DecodedJwtPayload, JwtPayload } from '@scaffoldly/serverless-util';
import { AccountDetail } from './Account';
import { Jwk } from './Jwt';
import { LoginDetail } from './Login';
import { AccountRow } from './models';
import { ProviderDetail, Provider } from './Provider';

export interface JWKSResponse {
  keys: Jwk[];
}

export type ProviderResponse = {
  [provider in Provider]: ProviderDetail;
};

export interface TokenResponse extends LoginDetail<JwtPayload> {
  token: string | null;
}

export interface LoginDetailResponse {
  payload: DecodedJwtPayload;
  providers: ProviderResponse;
}

export type Header = 'set-cookie';

export type TokenResponseHeaders = { [header in Header]?: string };

export type TokenResponseWithHeaders = {
  tokenResponse: TokenResponse;
  headers: TokenResponseHeaders;
};

export interface AuthorizeResponse {
  authorized: boolean;
  id?: string;
  payload?: DecodedJwtPayload;
  detail?: string;
}

export interface AccountResponse extends AccountRow {
  id: string;
  sk: string;
  detail: AccountDetail;
}

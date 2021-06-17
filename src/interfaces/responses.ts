import { DecodedJwtPayload, JwtPayload } from '@scaffoldly/serverless-util';
import { AccountDetail, LoginDetail, Provider } from '../models/interfaces';
import { Jwk } from './Jwt';
import { ProviderDetail } from './Provider';

export interface JWKSResponse {
  keys: Jwk[];
}

export type ProviderResponse = {
  [provider in Provider]: ProviderDetail;
};

export interface TokenResponse extends LoginDetail {
  token: string | null;
  payload: JwtPayload;
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

export interface AccountResponse extends AccountDetail {
  id: string;
}

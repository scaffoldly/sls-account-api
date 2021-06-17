import { Provider } from './Provider';

export type LoginRequestBase = {
  provider: Provider;
};

export type GoogleLoginRequest = {
  email: string;
  name?: string;
  id: string;
  idToken: string;
  authToken: string;
  photoUrl?: string;
};

export type EmailLoginRequest = {
  email: string;
  code?: string;
};

export type LoginRequest = LoginRequestBase & (EmailLoginRequest | GoogleLoginRequest);

export interface AuthorizeRequest {
  token: string;
}

export interface AccountRequest {
  name: string;
  email: string;
  company?: string;
}

export interface UpdateAccountRequest {
  name?: string;
  company?: string;
}

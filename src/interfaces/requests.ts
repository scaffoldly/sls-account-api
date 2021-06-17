import { EmailLogin, GoogleLogin } from '../models/interfaces';

export type GoogleLoginRequest = GoogleLogin;

export interface EmailLoginRequest extends EmailLogin {
  code?: string;
}

export type LoginRequest = EmailLoginRequest | GoogleLoginRequest;

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

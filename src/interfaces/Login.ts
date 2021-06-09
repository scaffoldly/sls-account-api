import { Provider } from './Provider';
import { VerificationMethod } from './Totp';

export interface VerificationResultBase {
  verified: boolean;
  verificationMethod: VerificationMethod;
  email: string;
  name?: string;
  photoUrl?: string;
  // + Any other properties the backend should return on successful login
}

export interface LoginDetail<T> extends VerificationResultBase {
  id: string;
  provider: Provider;
  payload: T;
}

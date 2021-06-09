import { AccountRequest } from './requests';

export interface AccountDetail extends AccountRequest {
  name: string;
  email: string;
  company?: string;
}

import { AccountDetail } from './Account';
import { RefreshDetail } from './Jwt';
import { LoginDetail } from './Login';
import { LoginRequest } from './requests';
import { TotpDetail } from './Totp';

export interface AccountsRowBase {
  id: string;
  sk: string;
}

export interface AccountsRow<T> extends AccountsRowBase {
  detail: T;
}

export type TotpRow = AccountsRow<TotpDetail>;
export type LoginRow = AccountsRow<LoginDetail<LoginRequest>>;
export type RefreshRow = AccountsRow<RefreshDetail>;
export type AccountRow = AccountsRow<AccountDetail>;

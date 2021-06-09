import { DecodedJwtPayload, HttpError } from '@scaffoldly/serverless-util';
import { AccountRow } from '../interfaces/models';
import { AccountRequest, UpdateAccountRequest } from '../interfaces/requests';
import { AccountResponse } from '../interfaces/responses';
import AccountsModel from '../models/AccountsModel';

export default class AccountService {
  accounts: AccountsModel<AccountRow>;

  constructor() {
    this.accounts = new AccountsModel();
  }

  async createAccount(request: AccountRequest, user: DecodedJwtPayload): Promise<AccountResponse> {
    const accountRow = await this.accounts.model.create({
      id: user.id,
      sk: 'primary',
      detail: request,
    });

    return accountRow.attrs as AccountResponse;
  }

  async updateAccount(
    request: UpdateAccountRequest,
    user: DecodedJwtPayload,
  ): Promise<AccountResponse> {
    let accountRow = await this.accounts.model.get(user.id, 'primary');
    if (!accountRow) {
      throw new HttpError(404, 'Not found');
    }

    accountRow = await this.accounts.model.update({
      ...accountRow.attrs,
      detail: { ...accountRow.attrs.detail, ...request },
    });

    return accountRow.attrs as AccountResponse;
  }

  async getAccount(user: DecodedJwtPayload): Promise<AccountResponse> {
    const accountRow = await this.accounts.model.get(user.id, 'primary');
    if (!accountRow) {
      throw new HttpError(404, 'Not found');
    }

    return accountRow.attrs as AccountResponse;
  }

  async getAccountById(id: string, user: DecodedJwtPayload): Promise<AccountResponse> {
    if (id !== user.id && id !== 'me') {
      throw new HttpError(403, 'Forbidden');
    }

    const accountRow: AccountRow = await this.getAccount(user);

    return accountRow as AccountResponse;
  }
}

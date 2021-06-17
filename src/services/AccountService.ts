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

    return {
      id: accountRow.attrs.id,
      ...accountRow.attrs.detail,
    };
  }

  async updateAccount(
    request: UpdateAccountRequest,
    user: DecodedJwtPayload,
  ): Promise<AccountResponse> {
    let accountRow = await this.accounts.model.get(user.id, 'primary');
    if (!accountRow) {
      throw new HttpError(404, 'Not Found');
    }

    accountRow = await this.accounts.model.update({
      ...accountRow.attrs,
      detail: { ...accountRow.attrs.detail, ...request },
    });

    return {
      id: accountRow.attrs.id,
      ...accountRow.attrs.detail,
    };
  }

  async getAccount(user: DecodedJwtPayload): Promise<AccountResponse> {
    const accountRow = await this.accounts.model.get(user.id, 'primary');
    if (!accountRow) {
      throw new HttpError(404, 'Not Found');
    }

    return {
      id: accountRow.attrs.id,
      ...accountRow.attrs.detail,
    };
  }

  async getAccountById(id: string, user: DecodedJwtPayload): Promise<AccountResponse> {
    if (id !== user.id && id !== 'me') {
      throw new HttpError(501, 'Not Implemented');
    }

    const account = await this.getAccount(user);

    return account;
  }
}

import { DecodedJwtPayload, HttpError } from '@scaffoldly/serverless-util';
import { AccountRequest, UpdateAccountRequest } from '../interfaces/requests';
import { AccountResponse } from '../interfaces/responses';
import { AccountModel } from '../models/AccountModel';

export default class AccountService {
  accountModel: AccountModel;

  constructor() {
    this.accountModel = new AccountModel();
  }

  async createAccount(request: AccountRequest, user: DecodedJwtPayload): Promise<AccountResponse> {
    const accountRow = await this.accountModel.model.create({
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
    let accountRow = await this.accountModel.model.get(user.id, 'primary');
    if (!accountRow) {
      throw new HttpError(404, 'Not Found');
    }

    accountRow = await this.accountModel.model.update({
      ...accountRow.attrs,
      detail: { ...accountRow.attrs.detail, ...request },
    });

    return {
      id: accountRow.attrs.id,
      ...accountRow.attrs.detail,
    };
  }

  async getAccount(user: DecodedJwtPayload): Promise<AccountResponse> {
    const accountRow = await this.accountModel.model.get(user.id, 'primary');
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

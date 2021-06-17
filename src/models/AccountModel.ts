import { Model, SERVICE_NAME, STAGE, Table } from '@scaffoldly/serverless-util';
import { TABLE_SUFFIX } from 'src/constants';
import { Account } from './interfaces';
import { account } from './schemas/Account';

export class AccountModel {
  public readonly table: Table<Account>;

  public readonly model: Model<Account>;

  constructor() {
    this.table = new Table(TABLE_SUFFIX, SERVICE_NAME, STAGE, account, 'id', 'sk');

    this.model = this.table.model;
  }
}

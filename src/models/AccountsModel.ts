import { Joi, Model, SERVICE_NAME, STAGE, Table } from '@scaffoldly/serverless-util';
import { ACCOUNTS_TABLE } from '../constants';

// TODO: Move typing helpers to serverless-util
export default class AccountsModel<T> {
  public readonly table: Table<T>;

  public readonly model: Model<T>;

  constructor() {
    this.table = new Table(
      ACCOUNTS_TABLE,
      SERVICE_NAME,
      STAGE,
      {
        id: Joi.string().required(),
        sk: Joi.string().required(),
        detail: Joi.any(), // TODO: Define schema
      },
      'id',
      'sk',
    );

    this.model = this.table.model;
  }
}

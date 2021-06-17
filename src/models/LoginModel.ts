import { Model, SERVICE_NAME, STAGE, Table } from '@scaffoldly/serverless-util';
import { TABLE_SUFFIX } from 'src/constants';
import { Login } from './interfaces';
import { login } from './schemas/Login';

export class LoginModel {
  public readonly table: Table<Login>;

  public readonly model: Model<Login>;

  constructor() {
    this.table = new Table(TABLE_SUFFIX, SERVICE_NAME, STAGE, login, 'id', 'sk');

    this.model = this.table.model;
  }
}

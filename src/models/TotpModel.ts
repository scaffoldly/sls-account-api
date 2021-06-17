import { Model, SERVICE_NAME, STAGE, Table } from '@scaffoldly/serverless-util';
import { TABLE_SUFFIX } from 'src/constants';
import { Totp } from './interfaces';
import { totp } from './schemas/Totp';

export class TotpModel {
  public readonly table: Table<Totp>;

  public readonly model: Model<Totp>;

  constructor() {
    this.table = new Table(TABLE_SUFFIX, SERVICE_NAME, STAGE, totp, 'id', 'sk');

    this.model = this.table.model;
  }
}

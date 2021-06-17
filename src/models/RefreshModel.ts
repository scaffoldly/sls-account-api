import { Model, SERVICE_NAME, STAGE, Table } from '@scaffoldly/serverless-util';
import { TABLE_SUFFIX } from 'src/constants';
import { Refresh } from './interfaces';
import { refresh } from './schemas/Refresh';

export class RefreshModel {
  public readonly table: Table<Refresh>;

  public readonly model: Model<Refresh>;

  constructor() {
    this.table = new Table(TABLE_SUFFIX, SERVICE_NAME, STAGE, refresh, 'id', 'sk');

    this.model = this.table.model;
  }
}

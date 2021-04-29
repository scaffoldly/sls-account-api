import { STAGE, SERVICE_NAME, Joi, Table } from '@scaffoldly/serverless-util';
import { ACCOUNTS_TABLE } from './constants';

export const accountsTable = new Table(
  ACCOUNTS_TABLE,
  SERVICE_NAME,
  STAGE,
  {
    id: Joi.string().required(),
    sk: Joi.string().required(),
    detail: Joi.any(), // TODO: Define schema
  },
  'id',
  'sk'
);

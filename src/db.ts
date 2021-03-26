import { STAGE, SERVICE_NAME, Joi, Table } from '@scaffoldly/serverless-util';
import { ACCOUNTS_TABLE } from './constants';

export const accountsTable = new Table(
  ACCOUNTS_TABLE,
  SERVICE_NAME,
  STAGE,
  {
    id: Joi.string(),
    sk: Joi.string(),
    name: Joi.string(),
    company: Joi.string().allow(null, ''),
    email: Joi.string(),
    twilioNumber: Joi.string(),
    allowedSenders: Joi.array(),
    idToken: Joi.string(),
    authToken: Joi.string(),
    provider: Joi.string(),
    photoUrl: Joi.string(),
    token: Joi.string(),
    header: Joi.string(),
    expires: Joi.number(),
    baseUrl: Joi.string(),
  },
  'id',
  'sk'
);

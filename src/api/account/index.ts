import {
  handleError,
  handleSuccess,
  HttpError,
  optionalParameters,
  requiredParameters,
} from '@scaffoldly/serverless-util';
import { APIGatewayProxyResult, Context } from 'aws-lambda';
import { accountsTable } from 'src/db';

import * as dotenv from 'dotenv';
import { AuthorizedEvent, GetIdentity } from '@scaffoldly/serverless-util/dist/auth';
import { PrimaryAccount } from 'src/types';
dotenv.config();

export const postV1 = async (
  event: AuthorizedEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const id = await GetIdentity(event, context);

    const params = requiredParameters(event.body, ['name', 'email']);
    const optParams = optionalParameters(event.body, ['company']);

    const { attrs: row }: { attrs: PrimaryAccount } = await accountsTable.model.create(
      {
        id,
        sk: 'primary',
        detail: {
          ...params,
          ...optParams,
        },
      },
      { overwrite: false }
    );

    console.log('Created account', row);

    return handleSuccess(event, row);
  } catch (e) {
    return handleError(event, e);
  }
};

export const patchByIdV1 = async (
  event: AuthorizedEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const id = await GetIdentity(event, context);

    const pathParams = requiredParameters(event.pathParameters, ['id']);

    // TODO: Support other IDs based on permissions
    if (pathParams.id !== id) {
      throw new HttpError(403, 'Forbidden');
    }

    // TODO: email address changes
    const bodyParams = optionalParameters(event.body, ['name', 'company'], {
      allowEmptyStrings: true,
    });

    const { attrs: existingRow }: { attrs: PrimaryAccount } =
      (await accountsTable.model.get(id, 'primary', {})) || {};

    if (!existingRow) {
      throw new HttpError(404, `Unable to find account with id ${id}`);
    }

    const { attrs: row }: { attrs: PrimaryAccount } = await accountsTable.model.update({
      ...existingRow,
      detail: {
        ...existingRow.detail,
        ...bodyParams,
      },
    });

    console.log('Updated account', row);

    return handleSuccess(event, row);
  } catch (e) {
    return handleError(event, e);
  }
};

export const getByIdV1 = async (
  event: AuthorizedEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const id = await GetIdentity(event, context);

    const pathParams = requiredParameters(event.pathParameters, ['id']);

    // TODO: Support other IDs based on permissions
    if (pathParams.id !== id) {
      throw new HttpError(403, 'Forbidden');
    }

    const { attrs: row }: { attrs: PrimaryAccount } =
      (await accountsTable.model.get(id, 'primary', {})) || {};

    if (!row) {
      throw new HttpError(404, `Unable to find account with id ${id}`);
    }

    return handleSuccess(event, row);
  } catch (e) {
    return handleError(event, e);
  }
};

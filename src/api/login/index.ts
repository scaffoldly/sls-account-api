import { handleError, handleSuccess } from '@scaffoldly/serverless-util';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { accountsTable } from 'src/db';
import { createEmptyToken, createRefreshToken, createToken } from 'src/jwt';
import { verifyLogin } from 'src/login';
import { CleansedObject, Login } from 'src/types';
import { cleanseObject, stringifyRedacted } from 'src/util';

import * as dotenv from 'dotenv';
import { AuthorizedEvent, GetIdentity } from '@scaffoldly/serverless-util/dist/auth';
dotenv.config();

export const optionsV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const headers = { 'Access-Control-Allow-Methods': 'GET,POST,DELETE', 'X-Auth-Refresh': 'true' };

  return handleSuccess(event, {}, { headers });
};

export const getV1 = async (
  event: AuthorizedEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const id = await GetIdentity(event, context);

  try {
    const result: [{ Items: [{ attrs: Login }] }] = await accountsTable.model
      .query(id)
      .where('sk')
      .beginsWith('login_')
      .exec()
      .promise();

    const items = result[0].Items.reduce((acc, item) => {
      const { provider } = item.attrs.detail;
      acc[provider] = cleanseObject(item.attrs);
      return acc;
    }, {} as { [key: string]: CleansedObject });

    return handleSuccess(event, items);
  } catch (e) {
    return handleError(event, e);
  }
};

export const postV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const result = await verifyLogin(event.body);

    const { attrs: login }: { attrs: Login } = await accountsTable.model.create(
      {
        id: result.id,
        sk: `login_${result.provider}_${result.id}`,
        detail: result,
      },
      { overwrite: true }
    );

    if (!result.verified) {
      return handleSuccess(event, createEmptyToken(login, event));
    }

    const refresh = await createRefreshToken(login.id, login.sk, event);

    const headers = {};
    if (event.headers['x-auth-refresh']) {
      headers['x-auth-refresh'] = event.headers['x-auth-refresh'];
    }

    const ret = handleSuccess(event, await createToken(login, event), {
      headers,
    });

    ret.headers['Set-Cookie'] = refresh.detail.header;

    return ret;
  } catch (e) {
    return handleError(event, e);
  }
};

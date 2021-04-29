import { handleError, handleSuccess } from '@scaffoldly/serverless-util';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { accountsTable } from 'src/db';
import { createRefreshToken, createToken, fetchRefreshRecord } from 'src/jwt';

import * as dotenv from 'dotenv';
import { Login } from 'src/types';
dotenv.config();

export const postV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const refreshRecord = await fetchRefreshRecord(event);
    if (!refreshRecord) {
      console.warn(`Unable to find refresh record`);
      return handleError(event, 'Unable to find/match refresh record', { statusCode: 403 });
    }

    const { id, detail } = refreshRecord;
    const { sk } = detail;

    const { attrs: login }: { attrs: Login } = (await accountsTable.model.get(id, sk, {})) || {};

    if (!login) {
      console.warn(`Unable to find existing login with ${id} ${sk}`);
      return handleError(event, 'Unable to find existing login', { statusCode: 403 });
    }

    console.log(`Generating new tokens for ${id} ${sk}`);

    // Tiny hack for consistency: lob off `/refresh` from the event path
    // TODO: Preserve Type
    const newEvent = JSON.parse(JSON.stringify(event));
    newEvent.path = newEvent.path.split('/').slice(0, -1).join('/');

    const refresh = await createRefreshToken(
      login.id,
      login.sk,
      newEvent,
      refreshRecord.detail.token
    );
    const ret = handleSuccess(event, await createToken(login, newEvent));

    ret.headers['Set-Cookie'] = refresh.detail.header;

    return ret;
  } catch (e) {
    return handleError(event, e);
  }
};

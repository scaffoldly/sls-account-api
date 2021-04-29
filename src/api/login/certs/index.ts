import { handleError, handleSuccess } from '@scaffoldly/serverless-util';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { getPublicKey } from 'src/jwt';
import { stringifyRedacted } from 'src/util';

import * as dotenv from 'dotenv';
dotenv.config();

export const getV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const publicKey = await getPublicKey();
    return handleSuccess(event, { keys: [publicKey] });
  } catch (e) {
    return handleError(event, e);
  }
};

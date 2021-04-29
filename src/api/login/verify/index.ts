import { handleError, handleSuccess, requiredParameters } from '@scaffoldly/serverless-util';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { verifyJwt } from 'src/jwt';
import { stringifyRedacted } from 'src/util';

import * as dotenv from 'dotenv';
dotenv.config();

export const postV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const params = requiredParameters(event.body, ['jwt', 'methodArn']);

    const { methodArn, jwt } = params;

    // TODO OAuth claims to methods
    console.log(`Verifying access to ${methodArn}`);

    const verified = await verifyJwt(jwt);

    return handleSuccess(event, verified);
  } catch (e) {
    return handleError(event, e);
  }
};

import { APIGatewayAuthorizerEvent, APIGatewayAuthorizerResult, Context } from 'aws-lambda';
import { verifyToken } from 'src/jwt';
import { stringifyRedacted } from 'src/util';

import * as dotenv from 'dotenv';
dotenv.config();

export const authorizeV1 = async (
  event: APIGatewayAuthorizerEvent,
  context: Context
): Promise<APIGatewayAuthorizerResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const { methodArn } = event;

  // TODO OAuth claims to methods
  console.log(`Verifying access to ${methodArn}`);

  const verified = await verifyToken(event);

  console.log('Verification result:', JSON.stringify(verified));

  // TODO: Scopes
  // TODO: Check resource path

  const response = {
    principalId: verified.principal,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect:
            !verified || !verified.authorized || !verified.payload || verified.error
              ? 'Deny'
              : 'Allow',
          Resource: methodArn,
        },
      ],
    },
    context: verified.payload,
  };

  console.log('Authorization result:', JSON.stringify(response, null, 2));

  return response;
};

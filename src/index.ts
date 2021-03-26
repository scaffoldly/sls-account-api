import * as dotenv from 'dotenv';
import {
  handleError,
  handleSuccess,
  requiredParameters,
  optionalParameters,
  HttpError,
} from '@scaffoldly/serverless-util';
import { cleanseObject, stringifyRedacted } from './util';
import { verifySocialToken } from './social';
import { accountsTable } from './db';
import {
  fetchRefreshRecord,
  createRefreshToken,
  createToken,
  getPublicKey,
  verifyToken,
} from './jwt';
import {
  APIGatewayAuthorizerEvent,
  APIGatewayAuthorizerResult,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { CleansedObject } from './types';
import * as serviceUrls from '../.scaffoldly/service-urls.json';
import * as sharedEnvVars from '../.scaffoldly/shared-env-vars.json';

dotenv.config();

// TODO: Env vars from .scaffoldly

export const createAccountV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const { requestContext } = event; // TODO Make this work locally for Authorizer Logins
    const { authorizer } = requestContext;

    const authorizerParams = optionalParameters(authorizer, ['apiKey', 'id']);
    const bodyParams = optionalParameters(event.body, ['id']);

    let id;
    if (authorizerParams.apiKey && bodyParams.id) {
      // Private API Call from Service
      id = bodyParams.id;
    } else if (authorizerParams.id) {
      // JWT Login verified by Authorizer
      id = authorizerParams.id;
    }

    if (!id) {
      throw new HttpError(400, 'Missing id from authorizer or path');
    }

    const params = requiredParameters(event.body, ['email', 'name']);
    const optParams = optionalParameters(event.body, ['company']);

    const row = await accountsTable.model.create(
      {
        id,
        sk: 'primary',
        ...params,
        ...optParams,
      },
      { overwrite: false }
    );

    console.log('Created account', row.attrs);

    return handleSuccess(event, row.attrs);
  } catch (e) {
    return handleError(event, e);
  }
};

export const updateAccountV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const { requestContext } = event; // TODO Make this work locally for Authorizer Logins
    const { authorizer } = requestContext;

    const authorizerParams = requiredParameters(authorizer, ['id']);
    const bodyParams = optionalParameters(event.body, ['name', 'company'], {
      allowEmptyStrings: true,
    });

    const existingRow = await accountsTable.model.get(authorizerParams.id, 'primary');

    if (!existingRow || !existingRow.attrs) {
      throw new HttpError(404, `Unable to find account with id ${authorizerParams.id}`);
    }

    const row = await accountsTable.model.create(
      {
        ...existingRow.attrs,
        ...bodyParams,
      },
      { overwrite: true }
    );

    console.log('Updated account', row.attrs);

    return handleSuccess(event, row.attrs);
  } catch (e) {
    return handleError(event, e);
  }
};

export const getAccountV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const { requestContext } = event; // TODO Make this work locally for Authorizer Logins
    const { authorizer, identity } = requestContext;

    const identityParams = optionalParameters(identity, ['apiKey']);
    const authorizerParams = optionalParameters(authorizer, ['id']);
    const pathParams = optionalParameters(event.pathParameters, ['id']);

    let id: string;
    let sk: string;
    if (identityParams.apiKey && pathParams.id) {
      // Private API Call from Service
      id = pathParams.id;
      sk = 'root'; // TODO: Figure out if I should keep root or migrate to 'primary'
    } else if (authorizerParams.id) {
      // JWT Login verified by Authorizer
      id = authorizerParams.id;
      sk = 'primary';
    }

    if (!id) {
      throw new HttpError(400, 'Missing id from authorizer or path');
    }

    const row = await accountsTable.model.get(id, sk, {});

    if (!row || !row.attrs) {
      return handleSuccess(event, null, { statusCode: 204 });
    }

    return handleSuccess(event, row.attrs);
  } catch (e) {
    return handleError(event, e);
  }
};

export const authorizeV1 = async (
  event: APIGatewayAuthorizerEvent,
  context: Context
): Promise<APIGatewayAuthorizerResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const { methodArn } = event;

  console.log(`Verifying access to ${methodArn}`);

  const verified = await verifyToken(event);

  if (!verified || !verified.authorized || !verified.payload) {
    console.warn('Unauthorized', verified);
    throw new Error('Unauthorized');
  }

  // TODO: Scopes
  // TODO: Check resource path

  const response = {
    principalId: verified.principal,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: verified.authorized ? 'Allow' : 'Deny',
          Resource: methodArn,
        },
      ],
    },
    context: verified.payload,
  };

  console.log('Authorization result:', JSON.stringify(response, null, 2));

  return response;
};

export const loginOptionsV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  // TODO REMOVE
  console.log('!!! service urls', serviceUrls);
  console.log('!!! env vars', sharedEnvVars);

  return handleSuccess(
    event,
    {},
    { headers: { 'Access-Control-Allow-Methods': 'GET,POST,DELETE' } }
  );
};

export const getLoginCertsV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const publicKey = await getPublicKey();
    return handleSuccess(event, { keys: [publicKey] });
  } catch (e) {
    return handleError(event, e);
  }
};

export const getLoginsV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const { requestContext } = event; // TODO Make this work locally for authorizer logins
  const { authorizer } = requestContext;
  const { id } = authorizer;

  try {
    const result = await accountsTable.model
      .query(id)
      .where('sk')
      .beginsWith('login_')
      .exec()
      .promise();

    const items = result[0].Items.reduce((acc, item) => {
      const { provider } = item.attrs;
      acc[provider] = cleanseObject(item.attrs);
      return acc;
    }, {} as { [key: string]: CleansedObject });

    return handleSuccess(event, items);
  } catch (e) {
    return handleError(event, e);
  }
};

export const createLoginV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${stringifyRedacted(event)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const { headers } = event;

  const { Host } = headers;
  const ssl = headers['X-Forwarded-Proto'] === 'https';

  const baseUrl = `${ssl ? 'https' : 'http'}://${Host}`;

  try {
    const params = requiredParameters(event.body, [
      'id',
      'idToken',
      'authToken',
      'email',
      'name',
      'provider',
    ]);
    const optParams = optionalParameters(event.body, ['photoUrl']);

    await verifySocialToken(params.provider, params.idToken);

    const login = await accountsTable.model.create(
      {
        ...params,
        ...optParams,
        baseUrl,
        id: params.email,
        sk: `login_${params.provider}_${params.id}`,
      },
      { overwrite: true }
    );

    const payload = cleanseObject(login.attrs);

    const refresh = await createRefreshToken(login.get('id'), login.get('sk'), event);
    const ret = handleSuccess(event, await createToken(login.get('id'), payload, event));

    ret.headers['Set-Cookie'] = refresh.header;

    console.log('Payload:', payload);
    console.log('Refresh Token:', refresh.token);

    return ret;
  } catch (e) {
    return handleError(event, e);
  }
};

export const refreshLoginV1 = async (
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

    const { id, name } = refreshRecord;
    const login = await accountsTable.model.get(id, name, {});
    if (!login) {
      console.warn(`Unable to find existing login with ${id} ${name}`);
      return handleError(event, 'Unable to find existing login', { statusCode: 403 });
    }

    const payload = cleanseObject(login.attrs);

    console.log('Generating new tokens:', payload);

    // Tiny hack for consistency: lob off `/refresh` from the event path
    const newEvent = JSON.parse(JSON.stringify(event));
    newEvent.path = newEvent.path.split('/').slice(0, -1).join('/');

    const refresh = await createRefreshToken(
      login.get('id'),
      login.get('sk'),
      newEvent,
      refreshRecord.token
    );
    const ret = handleSuccess(event, await createToken(login.get('id'), payload, newEvent));

    ret.headers['Set-Cookie'] = refresh.header;

    console.log('Payload:', payload);
    console.log('Refresh Token:', refresh.token);

    return ret;
  } catch (e) {
    return handleError(event, e);
  }
};

export const deleteLoginV1 = async (
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> => {
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  try {
    const { requestContext } = event; // TODO Make this work locally for Authorizer Logins
    const { authorizer } = requestContext;

    const authorizerParams = requiredParameters(authorizer, ['id']);
    const queryParams = requiredParameters(event.queryStringParameters, ['provider']);

    const result = await accountsTable.model
      .query(authorizerParams.id)
      .where('sk')
      .beginsWith('login_')
      .exec()
      .promise();

    if (!result || !result[0] || !result[0].Items || result[0].Items.length === 0) {
      return handleError(event, 'Unable to find any logins', { statusCode: 404 });
    }

    const logins = result[0].Items.reduce(
      (acc, item) => {
        if (item.get('provider') === queryParams.provider) {
          acc.toDelete = item;
        }
        if (item.get('provider') !== queryParams.provider) {
          // eslint-disable-next-line no-param-reassign
          acc.switchTo = item;
        }
        return acc;
      },
      { toDelete: null, switchTo: null }
    );

    const { toDelete, switchTo } = logins;

    if (!toDelete) {
      return handleError(event, 'Unable to to find the requested login option to remove', {
        statusCode: 400,
      });
    }

    if (!switchTo) {
      return handleError(event, 'Unable to remove the only configured login option', {
        statusCode: 400,
      });
    }

    const deleted = await accountsTable.model.destroy(authorizerParams.id, toDelete.get(), {
      ReturnValues: true,
    });

    console.log(`Deleted ${deleted.id} ${deleted.sk}`);

    const refreshRecord = await fetchRefreshRecord(event);
    if (!refreshRecord) {
      console.warn(`Unable to find refresh record`);
      return handleError(event, 'Unable to find/match refresh record', { statusCode: 403 });
    }

    const payload = cleanseObject(switchTo.attrs);

    console.log('Generating new tokens:', payload);

    const refresh = await createRefreshToken(
      switchTo.get('id'),
      switchTo.get('sk'),
      event,
      refreshRecord.token
    );
    const ret = handleSuccess(event, await createToken(switchTo.get('id'), payload, event));

    ret.headers['Set-Cookie'] = refresh.header;

    console.log('Payload:', payload);
    console.log('Refresh Token:', refresh.token);

    return ret;
  } catch (e) {
    return handleError(event, e);
  }
};

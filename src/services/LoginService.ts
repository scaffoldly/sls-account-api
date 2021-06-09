import {
  DecodedJwtPayload,
  extractToken,
  HttpError,
  HttpRequest,
} from '@scaffoldly/serverless-util';
import * as Google from 'google-auth-library';
import { env } from 'src/env';
import { LoginDetail, VerificationResultBase } from 'src/interfaces/Login';
import { LoginRow } from 'src/interfaces/models';
import {
  AuthorizeRequest,
  EmailLoginRequest,
  GoogleLoginRequest,
  LoginRequest,
} from 'src/interfaces/requests';
import AccountsModel from 'src/models/AccountsModel';
import { Provider } from '../interfaces/Provider';
import {
  AuthorizeResponse,
  ProviderResponse,
  TokenResponseHeaders,
  TokenResponseWithHeaders,
} from '../interfaces/responses';
import JwtService from './JwtService';
import TotpService from './TotpService';

export default class LoginService {
  envVars = env.env_vars;

  jwtService: JwtService;

  totpService: TotpService;

  logins: AccountsModel<LoginRow>;

  constructor() {
    this.jwtService = new JwtService();
    this.totpService = new TotpService();
    this.logins = new AccountsModel();
  }

  login = async (login: LoginRequest, request: HttpRequest): Promise<TokenResponseWithHeaders> => {
    const loginRow = await this.verifyLogin(login);

    // Lob off last '/.+' from the path so refresh/authorize URLs are correct
    let { path } = request;
    path = path.replace(/(.+)(\/.+)$/gm, '$1');

    if (!loginRow.detail.verified) {
      return {
        tokenResponse: this.jwtService.createEmptyToken(loginRow, request, path),
        headers: {},
      };
    }

    const refreshRow = await this.jwtService.createRefreshToken(loginRow, request);
    const token = await this.jwtService.createToken(loginRow, request, path);

    const headers: TokenResponseHeaders = {
      'set-cookie': refreshRow.detail.header,
    };

    return { tokenResponse: token, headers };
  };

  refresh = async (request: HttpRequest): Promise<TokenResponseWithHeaders> => {
    let refreshRow = await this.jwtService.fetchRefreshRow(request);
    if (!refreshRow) {
      console.warn(`Unable to find refresh record`);
      throw new HttpError(403, 'Unable to find/match refresh record');
    }

    const { id, detail } = refreshRow;
    const { sk } = detail;

    const loginRow = await this.logins.model.get(id, sk);

    if (!loginRow) {
      console.warn(`Unable to find existing login with ${id} ${sk}`);
      throw new HttpError(403, 'Unable to find existing login');
    }

    console.log(`Generating new tokens for ${id} ${sk}`);

    // Lob off last '/.+' from the path so refresh/authorize URLs are correct
    let { path } = request;
    path = path.replace(/(.+)(\/.+)$/gm, '$1');

    refreshRow = await this.jwtService.createRefreshToken(
      loginRow.attrs,
      request,
      refreshRow.detail.token,
    );
    const tokenResponse = await this.jwtService.createToken(loginRow.attrs, request, path);
    const headers: TokenResponseHeaders = {
      'set-cookie': refreshRow.detail.header,
    };

    return { tokenResponse, headers };
  };

  authorize = async (authorize: AuthorizeRequest): Promise<AuthorizeResponse> => {
    const response: AuthorizeResponse = {
      id: undefined,
      authorized: false,
      payload: undefined,
      detail: undefined,
    };

    if (!authorize || !authorize.token) {
      response.detail = 'Missing token from authorize request';
      return response;
    }

    const token = extractToken(authorize.token);
    if (!token) {
      response.detail = 'Unable to extract token';
      return response;
    }

    let payload: DecodedJwtPayload;
    try {
      payload = await this.jwtService.verifyJwt(token);
    } catch (e) {
      response.detail = e.message || e.name || 'Unexpected error verifying JWT';
      return response;
    }

    response.id = payload.id;
    response.authorized = true;
    response.payload = payload;

    return response;
  };

  async providers(id: string, user: DecodedJwtPayload): Promise<ProviderResponse> {
    if (id !== user.id && id !== 'me') {
      throw new HttpError(403, 'Forbidden');
    }

    const [result] = await this.logins.model
      .query(user.id)
      .where('sk')
      .beginsWith('login_')
      .exec()
      .promise();

    const initialResponse = {
      [Provider.Email]: {
        enabled: false,
        name: 'Email',
        clientId: this.envVars.MAIL_DOMAIN || undefined,
      },
      [Provider.Google]: {
        enabled: false,
        name: 'Google',
        clientId: this.envVars.GOOGLE_CLIENT_ID || undefined,
      },
    } as ProviderResponse;

    return result.Items.reduce((response, item) => {
      response[item.attrs.detail.provider] = {
        ...response[item.attrs.detail.provider],
        enabled: true,
      };
      return response;
    }, initialResponse);
  }

  private verifyLogin = async (login: LoginRequest): Promise<LoginRow> => {
    const email = login.email.trim().toLowerCase();

    let loginDetail: LoginDetail<LoginRequest> | undefined;
    const id = this.jwtService.generateAudience(email);

    switch (login.provider) {
      case 'GOOGLE': {
        const result = await this.verifyGoogleToken((login as GoogleLoginRequest).idToken);
        loginDetail = {
          ...result,
          id,
          provider: Provider.Google,
          payload: login,
        };
        break;
      }
      case 'EMAIL': {
        const result = await this.verifyEmail(id, email, (login as EmailLoginRequest).code);
        loginDetail = {
          ...result,
          id,
          provider: Provider.Email,
          payload: { ...login, code: undefined }, // Remove code from the response
        };
        break;
      }
      default:
        loginDetail = undefined;
    }

    if (!loginDetail) {
      throw new HttpError(400, 'Unknown provider');
    }

    const loginRow = await this.logins.model.create(
      {
        id: loginDetail.id,
        sk: `login_${loginDetail.provider}_${loginDetail.id}`,
        detail: loginDetail,
      },
      { overwrite: true },
    );

    return loginRow.attrs;
  };

  private verifyGoogleToken = async (token: string): Promise<VerificationResultBase> => {
    const client = new Google.OAuth2Client({ clientId: env.env_vars.GOOGLE_CLIENT_ID });

    let result: Google.LoginTicket;
    try {
      result = await client.verifyIdToken({ idToken: token });
    } catch (e) {
      throw new HttpError(401, 'Unauthorized', e);
    }

    if (!result) {
      throw new HttpError(500, 'Verification result was not set');
    }

    const payload = result.getPayload();

    if (!payload) {
      throw new HttpError(500, 'Verification payload was not set');
    }

    // eslint-disable-next-line @typescript-eslint/naming-convention
    const { sub, email, email_verified, picture } = payload;

    if (!sub) {
      throw new HttpError(500, 'Verification sub was not set');
    }

    if (!email) {
      throw new HttpError(400, 'Email scope not authorized');
    }

    return {
      verified: email_verified || false,
      verificationMethod: email_verified ? 'NONE' : 'EMAIL',
      email,
      photoUrl: picture,
    };
  };

  private verifyEmail = async (
    id: string,
    email: string,
    code?: string,
  ): Promise<VerificationResultBase> => {
    if (code) {
      const verified = await this.totpService.verifyTotp(id, email, code);
      return { verified, verificationMethod: 'EMAIL', email };
    }

    const verificationMethod = await this.totpService.sendTotp(id, email);
    return { verified: false, verificationMethod, email };
  };
}

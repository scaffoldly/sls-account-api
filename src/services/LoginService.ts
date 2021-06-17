import {
  DecodedJwtPayload,
  extractToken,
  HttpError,
  HttpRequest,
} from '@scaffoldly/serverless-util';
import * as Google from 'google-auth-library';
import { env } from '../env';
import {
  AuthorizeRequest,
  EmailLoginRequest,
  GoogleLoginRequest,
  LoginRequest,
} from '../interfaces/requests';
import {
  AuthorizeResponse,
  ProviderResponse,
  TokenResponseHeaders,
  TokenResponseWithHeaders,
} from '../interfaces/responses';
import { Login, LoginDetail, VerificationMethod } from '../models/interfaces';
import { LoginModel } from '../models/LoginModel';
import JwtService from './JwtService';
import TotpService from './TotpService';

interface VerificationResult {
  verified: boolean;
  verificationMethod: VerificationMethod;
  email: string;
  name?: string;
  photoUrl?: string;
}

export default class LoginService {
  jwtService: JwtService;

  totpService: TotpService;

  loginModel: LoginModel;

  constructor() {
    this.jwtService = new JwtService();
    this.totpService = new TotpService();
    this.loginModel = new LoginModel();
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

    const token = await this.jwtService.createToken(loginRow, request, path);
    const refreshRow = await this.jwtService.createRefreshToken(
      loginRow,
      request,
      token.payload.sessionId,
    );

    const headers: TokenResponseHeaders = {
      'set-cookie': refreshRow.detail.header,
    };

    return { tokenResponse: token, headers };
  };

  refresh = async (
    authorization: string,
    request: HttpRequest,
  ): Promise<TokenResponseWithHeaders> => {
    let refreshRow = await this.jwtService.fetchRefreshRow(authorization, request);
    if (!refreshRow) {
      console.warn(`Unable to find refresh record`);
      throw new HttpError(403, 'Unable to find/match refresh record');
    }

    const { id, detail } = refreshRow;
    const { sk } = detail;

    const loginRow = await this.loginModel.model.get(id, sk);

    if (!loginRow) {
      console.warn(`Unable to find existing login with ${id} ${sk}`);
      throw new HttpError(403, 'Unable to find existing login');
    }

    console.log(`Generating new tokens for ${id} ${sk}`);

    // Lob off last '/.+' from the path so refresh/authorize URLs are correct
    let { path } = request;
    path = path.replace(/(.+)(\/.+)$/gm, '$1');

    const tokenResponse = await this.jwtService.createToken(
      loginRow.attrs,
      request,
      path,
      refreshRow.detail.sessionId,
    );
    refreshRow = await this.jwtService.createRefreshToken(
      loginRow.attrs,
      request,
      refreshRow.detail.sessionId,
      refreshRow.detail.token,
    );
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

    const [result] = await this.loginModel.model
      .query(user.id)
      .where('sk')
      .beginsWith('login_')
      .exec()
      .promise();

    const initialResponse = {
      EMAIL: {
        enabled: false,
        name: 'Email',
        clientId: env.env_vars.MAIL_DOMAIN || undefined,
      },
      GOOGLE: {
        enabled: false,
        name: 'Google',
        clientId: env.env_vars.GOOGLE_CLIENT_ID || undefined,
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

  private verifyLogin = async (login: LoginRequest): Promise<Login> => {
    const email = login.email.trim().toLowerCase();

    let loginDetail: LoginDetail | undefined;
    const id = this.jwtService.generateAudience(email);

    switch (login.provider) {
      case 'GOOGLE': {
        const result = await this.verifyGoogleToken((login as GoogleLoginRequest).idToken);
        loginDetail = {
          ...result,
          id,
          provider: 'GOOGLE',
          request: login,
        };
        break;
      }
      case 'EMAIL': {
        const result = await this.verifyEmail(id, email, (login as EmailLoginRequest).code);
        loginDetail = {
          ...result,
          id,
          provider: 'EMAIL',
          request: login,
        };
        break;
      }
      default:
        loginDetail = undefined;
    }

    if (!loginDetail) {
      throw new HttpError(400, 'Unknown provider');
    }

    const loginRow = await this.loginModel.model.create(
      {
        id: loginDetail.id,
        sk: `login_${loginDetail.provider}_${loginDetail.id}`,
        detail: loginDetail,
      },
      { overwrite: true },
    );

    return loginRow.attrs;
  };

  private verifyGoogleToken = async (token: string): Promise<VerificationResult> => {
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
  ): Promise<VerificationResult> => {
    if (code) {
      const verified = await this.totpService.verifyTotp(id, email, code);
      return { verified, verificationMethod: 'EMAIL', email };
    }

    const verificationMethod = await this.totpService.sendTotp(id, email);
    return { verified: false, verificationMethod, email };
  };
}

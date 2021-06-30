import { ErrorResponse, HttpRequest, HttpRequestWithUser } from '@scaffoldly/serverless-util';
import {
  Body,
  Controller,
  Get,
  Header,
  Post,
  Request,
  Res,
  Response,
  Route,
  Security,
  Tags,
  TsoaResponse,
} from 'tsoa';
import { env } from '../env';
import { AuthorizeRequest, EmailLoginRequest, GoogleLoginRequest } from '../interfaces/requests';
import {
  AuthorizeResponse,
  JWKSResponse,
  LoginDetailResponse,
  ProviderResponse,
  TokenResponse,
} from '../interfaces/responses';
import AccountService from '../services/AccountService';
import JwtService from '../services/JwtService';
import LoginService from '../services/LoginService';
import ProviderService from '../services/ProviderService';

@Route(`/api/v1/jwt`)
@Tags('Jwt')
export class JwtControllerV1 extends Controller {
  loginService: LoginService;

  jwtService: JwtService;

  providerService: ProviderService;

  accountService: AccountService;

  constructor() {
    super();
    this.loginService = new LoginService();
    this.jwtService = new JwtService();
    this.providerService = new ProviderService();
    this.accountService = new AccountService();
  }

  @Post('email')
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Response<TokenResponse, { 'set-cookie'?: string }>(200)
  public async emailLogin(
    @Body() login: EmailLoginRequest,
    @Request() request: HttpRequest,
    @Res()
    res: TsoaResponse<200, TokenResponse, { 'set-cookie'?: string }>,
  ): Promise<TokenResponse> {
    const { tokenResponse, headers } = await this.loginService.login(
      { ...login, provider: 'EMAIL' },
      request,
    );
    const response = res(200, tokenResponse, headers);
    return response;
  }

  @Post('google')
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Response<TokenResponse, { 'set-cookie'?: string }>(200)
  public async googleLogin(
    @Body() login: GoogleLoginRequest,
    @Request() request: HttpRequest,
    @Res()
    res: TsoaResponse<200, TokenResponse, { 'set-cookie'?: string }>,
  ): Promise<TokenResponse> {
    const { tokenResponse, headers } = await this.loginService.login(
      { ...login, provider: 'GOOGLE' },
      request,
    );
    const response = res(200, tokenResponse, headers);
    return response;
  }

  @Get('me')
  @Security('jwt')
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  public async getLoginDetail(
    @Request() request: HttpRequestWithUser,
  ): Promise<LoginDetailResponse> {
    const response: LoginDetailResponse = {
      payload: request.user,
      providers: await this.loginService.providers('me', request.user),
    };
    return response;
  }

  @Post('refresh')
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Response<TokenResponse, { 'set-cookie'?: string }>(200)
  public async refresh(
    @Header() authorization: string,
    @Request() request: HttpRequest,
    @Res()
    res: TsoaResponse<200, TokenResponse, { 'set-cookie'?: string }>,
  ): Promise<TokenResponse> {
    const { tokenResponse, headers } = await this.loginService.refresh(authorization, request);
    const response = res(200, tokenResponse, headers);
    return response;
  }

  @Post('authorize')
  public async authorize(@Body() authorize: AuthorizeRequest): Promise<AuthorizeResponse> {
    const response = await this.loginService.authorize(authorize);
    return response;
  }

  @Get('certs')
  public async getCerts(): Promise<JWKSResponse> {
    const publicKey = await this.jwtService.getPublicKey();
    return { keys: [publicKey] };
  }

  @Get('providers')
  // eslint-disable-next-line class-methods-use-this
  public getProviders(): ProviderResponse {
    // TODO: Move the ProviderDetail generation into ProviderService
    const response: ProviderResponse = {
      GOOGLE: env.GOOGLE_CLIENT_ID
        ? { name: 'Google', clientId: env.GOOGLE_CLIENT_ID, enabled: true }
        : { enabled: false },
      EMAIL: env.MAIL_DOMAIN
        ? { name: 'Email', clientId: env.MAIL_DOMAIN, enabled: true }
        : { enabled: false },
    };

    return response;
  }
}

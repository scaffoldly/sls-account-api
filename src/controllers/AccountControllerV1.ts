import {
  Body,
  Controller,
  Get,
  Patch,
  Path,
  Post,
  Request,
  Response,
  Route,
  Security,
  Tags,
} from 'tsoa';
import { ErrorResponse, HttpRequestWithUser } from '@scaffoldly/serverless-util';
import { AccountRequest, UpdateAccountRequest } from '../interfaces/requests';
import { AccountResponse } from '../interfaces/responses';
import AccountService from '../services/AccountService';

@Route(`/api/v1/account`)
@Tags('Account')
export class AccountControllerV1 extends Controller {
  accountService: AccountService;

  constructor() {
    super();
    this.accountService = new AccountService();
  }

  @Get('me')
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Security('jwt')
  public async getMyAccount(@Request() request: HttpRequestWithUser): Promise<AccountResponse> {
    return this.getAccountById('me', request);
  }

  @Get('{id}')
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Security('jwt')
  public async getAccountById(
    @Path('id') id: string,
    @Request() request: HttpRequestWithUser,
  ): Promise<AccountResponse> {
    return this.accountService.getAccountById(id, request.user);
  }

  @Post()
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Security('jwt')
  public async createAccount(
    @Body() accountRequest: AccountRequest,
    @Request() request: HttpRequestWithUser,
  ): Promise<AccountResponse> {
    return this.accountService.createAccount(accountRequest, request.user);
  }

  @Patch()
  @Response<ErrorResponse>('4XX')
  @Response<ErrorResponse>('5XX')
  @Security('jwt')
  public async updateAccount(
    @Body() updateAccountRequest: UpdateAccountRequest,
    @Request() request: HttpRequestWithUser,
  ): Promise<AccountResponse> {
    return this.accountService.updateAccount(updateAccountRequest, request.user);
  }
}

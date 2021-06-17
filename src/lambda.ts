import { configure } from '@vendia/serverless-express';
import * as dotenv from 'dotenv';
import app from './app';

// import { AWS } from '@scaffoldly/serverless-util';
// AWS.config.logger = console;

dotenv.config();

exports.handler = configure({ app });

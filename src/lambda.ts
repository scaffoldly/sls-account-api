import { configure } from '@vendia/serverless-express';
import * as dotenv from 'dotenv';
import app from './app';

dotenv.config();

exports.handler = configure({ app });

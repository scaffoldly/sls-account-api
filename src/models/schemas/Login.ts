import Joi from 'joi';
import { verificationMethodSchema } from './Totp';

export const providerSchema = Joi.valid('EMAIL', 'GOOGLE').label('Provider');

export const emailLoginSchema = Joi.object({
  provider: Joi.valid('EMAIL').required(),
  email: Joi.string().required(),
  code: Joi.string().optional(),
}).label('EmailLogin');

export const googleLoginSchema = Joi.object({
  provider: Joi.valid('GOOGLE').required(),
  email: Joi.string().required(),
  name: Joi.string().optional(),
  id: Joi.string().required(),
  idToken: Joi.string().required(),
  authToken: Joi.string().required(),
  photoUrl: Joi.string().optional(),
}).label('GoogleLogin');

export const loginDetailSchema = Joi.object({
  id: Joi.string().required(),
  provider: providerSchema.required(),
  verified: Joi.boolean().required(),
  verificationMethod: verificationMethodSchema.required(),
  email: Joi.string().required(),
  name: Joi.string().optional(),
  photoUrl: Joi.string().optional(),
  request: Joi.alternatives().try(emailLoginSchema, googleLoginSchema).required(),
}).label('LoginDetail');

export const login = {
  id: Joi.string().required(),
  sk: Joi.string().required(),
  detail: loginDetailSchema.required(),
};

export const loginSchema = Joi.object(login).label('Login');

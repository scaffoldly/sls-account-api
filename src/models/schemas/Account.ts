import Joi from 'joi';

export const accountDetailSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().required(),
  company: Joi.string().optional(),
}).label('AccountDetail');

export const account = {
  id: Joi.string().required(),
  sk: Joi.string().required(),
  detail: accountDetailSchema.required(),
};

export const accountSchema = Joi.object(account).label('Account');

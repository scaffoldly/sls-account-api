import Joi from 'joi';

export const refreshDetailSchema = Joi.object({
  sk: Joi.string().required(),
  token: Joi.string().required(),
  expires: Joi.number().required(),
  header: Joi.string().required(),
  sessionId: Joi.string().required(),
}).label('RefreshDetail');

export const refresh = {
  id: Joi.string().required(),
  sk: Joi.string().required(),
  detail: refreshDetailSchema.required(),
};

export const refreshSchema = Joi.object(refresh).label('Refresh');

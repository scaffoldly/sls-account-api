import Joi from 'joi';

export const verificationMethodSchema = Joi.valid('EMAIL', 'AUTHENTICATOR', 'NONE').label(
  'VerificationMethod',
);

export const totpDetailSchema = Joi.object({
  secret: Joi.string().required(),
  verified: Joi.boolean().required(),
  authenticator: Joi.boolean().required(),
}).label('TotpDetail');

export const totp = {
  id: Joi.string().required(),
  sk: Joi.string().required(),
  detail: totpDetailSchema.required(),
};

export const totpSchema = Joi.object(totp).label('Totp');

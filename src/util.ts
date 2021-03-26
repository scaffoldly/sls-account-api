import { SENSITIVE_KEYS } from './constants';
import { CleansedObject, LoginTokenRequest } from './types';

export const stringifyRedacted = (obj: unknown): string => {
  const ret = JSON.parse(JSON.stringify(obj));
  Object.keys(ret).forEach((key) => {
    if (SENSITIVE_KEYS.includes(key.toLowerCase())) {
      if (Array.isArray(ret[key])) {
        ret[key] = ['**REDACTED**'];
      } else {
        ret[key] = '**REDACTED**';
      }
    } else if (ret[key] instanceof Object) {
      ret[key] = stringifyRedacted(ret[key]);
    }
  });

  return JSON.stringify(ret);
};

export const cleanseObject = (obj: LoginTokenRequest): CleansedObject => {
  const parsed = JSON.parse(JSON.stringify(obj));
  const cleansed = Object.entries(parsed).reduce((acc, [key, value]) => {
    if (SENSITIVE_KEYS.includes(key.toLowerCase())) {
      return acc;
    }

    if (typeof value === 'string' || value instanceof String) {
      acc[key] = value as string;
    }

    if (typeof value === 'number' || value instanceof Number) {
      acc[key] = value as number;
    }

    if (typeof value === 'boolean' || value instanceof Boolean) {
      acc[key] = value as boolean;
    }

    return acc;
  }, {} as CleansedObject);

  return cleansed;
};

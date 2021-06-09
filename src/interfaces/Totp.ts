export interface TotpDetail {
  secret: string;
  verified: boolean;
  authenticator: boolean;
}

export type VerificationMethod = 'EMAIL' | 'AUTHENTICATOR' | 'NONE';

export interface Jwk {
  kty: 'EC';
  crv: 'P-256';
  y: string;
  d?: string;
}

export interface PemJwk {
  pem: string;
  jwk: Jwk;
}

export interface GeneratedKeys {
  issuer: string;
  publicKey: PemJwk;
  privateKey: PemJwk;
}

export interface RefreshDetail {
  sk: string;
  token: string;
  expires: number;
  header: string;
}

export enum Provider {
  Google = 'GOOGLE',
  Email = 'EMAIL',
}

export interface ProviderDetail {
  enabled: boolean;
  name?: string;
  clientId?: string;
}

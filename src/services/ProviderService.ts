import { AWS } from '@scaffoldly/serverless-util';

export default class ProviderService {
  ses: AWS.SES;

  constructor() {
    this.ses = new AWS.SES();
  }

  isDomainVerified = async (domain: string): Promise<boolean> => {
    const verificationAttributes = await this.ses
      .getIdentityVerificationAttributes({ Identities: [domain] })
      .promise();
    const { VerificationAttributes } = verificationAttributes;
    if (!VerificationAttributes) {
      console.warn('Unable to find SES domain verification attributes', verificationAttributes);
      return false;
    }

    const attributes = VerificationAttributes[domain];
    if (!attributes) {
      console.warn(
        `Unable to find SES domain verification attributes for domain ${domain}`,
        verificationAttributes,
      );
      return false;
    }

    if (attributes.VerificationStatus !== 'Success') {
      console.warn(`SES domain ${domain} is not verified`, attributes);
      return false;
    }

    return true;
  };
}

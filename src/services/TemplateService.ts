import { STAGE, AWS } from '@scaffoldly/serverless-util';

import _ from 'lodash';
import { templates } from '../templates';

export default class TemplateService {
  ses: AWS.SES;

  constructor() {
    this.ses = new AWS.SES();
  }

  fetchTemplate = async (name: string): Promise<string> => {
    const templateName = `${name}-${STAGE}`;
    const template = templates[name];
    const source = {
      TemplateName: templateName,
      ...template,
    };

    let templateResponse: AWS.SES.GetTemplateResponse;
    try {
      templateResponse = await this.ses.getTemplate({ TemplateName: templateName }).promise();
    } catch (e) {
      console.log('Creating template', templateName);
      await this.ses.createTemplate({ Template: source }).promise();
      templateResponse = await this.ses.getTemplate({ TemplateName: templateName }).promise();
    }

    if (!_.isEqual(templateResponse.Template, source)) {
      console.log('Updating template', templateName);
      await this.ses.updateTemplate({ Template: source }).promise();
    }

    if (!templateResponse.Template) {
      throw new Error(`Unable to find template: ${name}`);
    }

    console.log('Using template', templateResponse.Template.TemplateName);
    return templateResponse.Template.TemplateName;
  };
}

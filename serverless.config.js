// eslint-disable-next-line @typescript-eslint/no-var-requires
const envVars = require('./.scaffoldly/env-vars.json');

// TODO: make safe for Windows
module.exports.repositoryName = envVars.APPLICATION_NAME;
module.exports.serviceName = envVars.SERVICE_NAME;

/* eslint-disable @typescript-eslint/no-var-requires */
const { generateRoutes, generateSpec } = require('tsoa');
const envVars = require('./.scaffoldly/env-vars.json');
const packageJson = require('./package.json');

(async () => {
  await generateSpec({
    basePath: `/${envVars.SERVICE_NAME}`,
    name: envVars.APPLICATION_NAME,
    version: packageJson.version,
    description: `To generate a JWT token, go to the <a href="https://${envVars.SERVERLESS_API_DOMAIN}/auth/jwt.html" target="_blank">JWT Token Generator</a>`,
    entryFile: 'src/app.ts',
    noImplicitAdditionalProperties: 'throw-on-extras',
    controllerPathGlobs: ['src/**/*Controller*.ts'],
    outputDirectory: 'src',
    specVersion: 3,
    securityDefinitions: {
      jwt: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    // spec: {
    //   servers: [
    //     {
    //       url: 'http://localhost:8080/api/v1',
    //       description: 'Local development',
    //     },
    //     {
    //       url: 'http://prod:8080/api/v1',
    //       description: 'Prod development',
    //     },
    //   ],
    // },
  });

  await generateRoutes({
    // basePath: `/${envVars.SERVICE_NAME}`,
    entryFile: 'src/app.ts',
    noImplicitAdditionalProperties: 'throw-on-extras',
    controllerPathGlobs: ['src/**/*Controller*.ts'],
    routesDir: 'src',
    authenticationModule: 'src/auth.ts',
    noWriteIfUnchanged: true,
  });
})();

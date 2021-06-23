# Authentication API

This is the centralized authentication API for this project

Fully functional (local and cloud) backend for execution in AWS Lambda and AWS
API Gateway, and deployed using GitHub Actions using the `serverless` tool.

This service is a micro-service so avoid globbing it with mutliple controllers,
unless absolutely necessary. Addtional services can be configured within the
`scaffoldly-bootstrap` project.

Generated using [Scaffoldly](https://scaffold.ly/). More information can be
found in the [Scaffoldly Documentation](https://docs.scaffold.ly/)

# Features

- Serverless
- JWT Token Generation/Refreshes
- JWT Token Generation Page
- Account Management (Email, Name, Company
- Automatic OpenAPI Specification

# Developing/Running/Debugging

1.  Clone this repository
1.  Run `yarn`
1.  Open the project in [VSCode](https://code.visualstudio.com/), and press `F5` to run.

From here, you'll see debug output in the terminal, you can add breakpoints
anywhere in the code to inspect and step through the code.

## API Docs

Once your service is up and running, you can see your API Docs by visiting:

```
http://localhost:3000/auth/openapi.json
```

# Releases/Deployments

Every commit to `main` triggers a Non-Live release. They can be viewed in GitHub
actions.

To release to Live, navigate to `Releases`, edit the desired release, then click
`Publish`.

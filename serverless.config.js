// TODO: make safe for Windows
module.exports.repositoryName = process.cwd().split('/').slice(-1)[0];
module.exports.serviceName = process.cwd().split('/').slice(-1)[0].split('-')[1];

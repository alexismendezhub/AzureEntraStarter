const { env } = require('process');

// Same as the VS template: points at the HTTPS port of the Server that SpaProxy launched.
const target = env.ASPNETCORE_HTTPS_PORT
  ? `https://localhost:${env.ASPNETCORE_HTTPS_PORT}`
  : env.ASPNETCORE_URLS
    ? env.ASPNETCORE_URLS.split(';')[0]
    : 'https://localhost:7190';

const PROXY_CONFIG = [
  {
    // /api includes the OpenID Connect callback (/api/auth/oidc/callback). The Host header is kept (changeOrigin: false),
    // so the server builds the redirect URI with this dev-server address: https://localhost:63431/api/auth/oidc/callback.
    context: ['/api', '/.well-known', '/health'],
    target,
    secure: false,
    changeOrigin: false,
    xfwd: false,
  },
];

module.exports = PROXY_CONFIG;

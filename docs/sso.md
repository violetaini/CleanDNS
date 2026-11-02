# Management SSO

CleanDNS supports an optional Chitanda SSO identity agent for its browser administration and management APIs. The default `CLEANDNS_AUTH_MODE=local` keeps the standalone administrator login. `CLEANDNS_AUTH_MODE=sso` requires a fixed loopback agent and disables password login and legacy CleanDNS sessions for management access.

DoH requests are handled before management authentication. Native DoQ, plain DNS, and their existing access controls remain independent of browser SSO. Enabling SSO does not enable any disabled DNS listener or change its endpoint.

## Configure

Install the Chitanda SSO agent separately, register an OAuth client with a fixed callback URL, and configure an explicit administrator subject allowlist in the agent. The agent holds OAuth credentials and tokens; this public repository contains only the loopback application adapter.

Create a private application configuration readable by the CleanDNS service, for example `/etc/cleandns-sso.json`:

```json
{
  "origin": "https://dns.example.com",
  "issuer": "https://sso.example.com",
  "agentURL": "http://127.0.0.1:9789/cleandns",
  "key": "REPLACE_WITH_A_RANDOM_AGENT_CREDENTIAL_AT_LEAST_32_CHARACTERS",
  "panelPath": "/admin/",
  "apiBase": "/api",
  "allowedOrigins": []
}
```

The key must match the separately configured agent application. Use file mode `0600`, or a narrowly scoped service group if CleanDNS runs without root. Keep credentials and runtime files out of Git. `agentURL` must be loopback HTTP with a fixed application name; `origin` and `issuer` must be fixed HTTPS origins. Optional additional browser origins must use the same hostname over HTTPS, for example an explicitly supported alternate HTTPS port.

Set these environment variables in the service:

```ini
Environment=CLEANDNS_AUTH_MODE=sso
Environment=CLEANDNS_SSO_CONFIG_FILE=/etc/cleandns-sso.json
```

The agent callback URL is `origin + apiBase + /sso/callback`, and its landing path is `panelPath`. Public paths may use a deployment-specific prefix; the reverse proxy must map that API prefix to CleanDNS `/api/` and the panel prefix to its panel handler. CleanDNS supplies the frontend API prefix from the private configuration, without exposing the agent key.

Keep the CleanDNS HTTP listener on loopback. The trusted proxy must overwrite `X-Real-IP` with a verified original visitor address. With multiple proxies, authenticate the adjacent hop before accepting its visitor address. Keep Host/SNI validation and the fixed-origin restriction on every public ingress.

## Behavior

- An anonymous panel visit starts SSO. Unauthenticated management requests fail closed; identity-agent failures return `503`.
- The agent performs OIDC state, PKCE, token, role, subject and session checks. Access is restricted to the configured administrator subjects.
- Mutating management requests require a valid session, an allowed browser Origin, and `X-CSRF-Token`. The frontend obtains the token from `/api/session` and keeps it in memory.
- Password login is rejected in SSO mode, including attempts with legacy CleanDNS session cookies.
- Logout removes the application session and continues to SSO logout confirmation. Background refreshes cannot restart login while logout is in progress.
- A revoked SSO session is rejected through agent validation. Read-validation caching is controlled by the identity agent; the deployed Chitanda agent uses a short five-second read cache and forces validation for mutations.

## Verification

```bash
npm run test:sso
npm test
```

The SSO suite covers password bypass rejection, role denial, callback/redirect handling, CSRF, alternate allowed Origins, session revocation, identity-agent failure, logout and anonymous DoH GET/POST. Verify a real OIDC sign-in, global logout, and DNS queries through the production proxy before exposing the management entry. Configure the application's callback to handle the `loggedout=1` return without consuming it as an authorization code.

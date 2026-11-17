# DevOidc

An OpenID Connect provider for **local testing only**. It signs anyone in as anyone, with no
password, so that a developer or a test script can get tokens for a local API and a local
single-page application without going through the real identity provider.

> **Never deploy it, and never let a real environment trust it.** Whoever can reach DevOidc can be
> any user. It listens on this computer's loopback addresses only, refuses callers from other
> machines, and has no deployment script on purpose.

It is one file, `Program.cs`, on .NET 10, with no packages.

## Why

An application that signs in at Azure AD B2C, Entra ID or any hosted provider needs a person, a
password and a browser before a single signed-in call can be made. That stops automated tests, and
it makes "what does this page look like for a user with that role" a five-minute job. With DevOidc:

- the application signs in through its normal OpenID Connect code (authorization code with PKCE),
  and the sign-in page is a list of test users, one click each;
- a script gets a token for any user with one HTTP call;
- a script can ask for tokens that **must be refused** (expired, another audience, an old sign-in),
  to test that the API refuses them.

The API under test keeps validating tokens properly: signature against the published key, issuer,
audience, lifetime. Only the provider is a stand-in.

## Run it

```
dotnet run -c Release -- --config path\to\my-project.json
```

| Argument | Meaning |
|---|---|
| `--config <file>` | A project's clients and users (format below). Repeat it to serve several projects from one DevOidc. Required. |
| `--port <n>` | Default `5443`. The issuer is always `https://localhost:<port>`. |
| `--cert-pem <file> --key-pem <file>` | A TLS certificate to serve instead of the ASP.NET Core development certificate. |

On start it prints its issuer, the clients it knows and where its signing key is. `https://localhost:5443/`
shows the same in a browser.

**The certificate.** Without `--cert-pem`, DevOidc serves the ASP.NET Core development certificate.
Trust it once with `dotnet dev-certs https --trust`: the browser and the API both have to accept it.
It lasts a year.

## A project's configuration file

Each project that tests against DevOidc keeps its own file, in its own repository:

```json
{
  "clients": [
    {
      "client_id": "7f1c2a9e-0000-4000-8000-000000000001",
      "name": "My application (local)",
      "redirect_uris": ["https://myapp.test/auth/callback"],
      "post_logout_redirect_uris": ["https://myapp.test/login"],
      "access_token": true,
      "token_lifetime_seconds": 3600
    }
  ],
  "users": [
    { "email": "admin@example.test", "name": "Ada Admin", "note": "administrator" },
    { "email": "reader@example.test", "name": "Rob Reader", "given_name": "Rob", "family_name": "Reader" }
  ]
}
```

- `client_id` is whatever the application sends and the API expects as the token's audience. Make
  one up for local use; do not reuse a real environment's.
- `redirect_uris` must match what the application sends exactly. Their origins are also the only
  origins allowed to call DevOidc from a browser (CORS).
- `post_logout_redirect_uris` are matched without their query, so the application may add its own
  (`/login?reason=...`).
- `access_token`: `true` (the default) also returns the signed token as `access_token`. Set it to
  `false` to behave like Azure AD B2C when no API scope is asked for: an ID token and a refresh
  token, no access token.
- `token_lifetime_seconds`: default 3600. Set it low for a while to watch the application renew.
- `users` are the buttons on the sign-in page. `given_name` and `family_name` default to the first
  word of `name` and the rest; `note` is shown under the e-mail. Any other e-mail can be typed on
  the page: its name is made from the address.

A saved file is read again on the next request. If the new content is unusable, the last good one
stays and the console says why.

## Getting a token

**Through the page.** The application redirects to `/authorize` as with any provider. The page
lists the users; a click returns to the application with a code. `prompt=login` shows the page, as
does everything else: DevOidc keeps no browser session, so `prompt=none` answers `login_required`.

**Without the page**, for scripts:

```
curl -s https://localhost:5443/token -d grant_type=urn:devoidc:user \
     -d client_id=7f1c2a9e-0000-4000-8000-000000000001 -d email=admin@example.test
```

The answer's `id_token` (and `access_token`, the same token) is what goes in
`Authorization: Bearer ...`. Optional fields, for tokens the API should refuse:

| Field | Effect |
|---|---|
| `lifetime_seconds` | The token's lifetime. A negative number gives a token that has already expired, by that many seconds. |
| `auth_time` | The moment of sign-in, in seconds since 1970, instead of now. For an API that refuses sessions older than a sign-out. |
| `aud` | The audience, instead of the client id. |
| `nonce` | Put into the token as given. |

## What a token holds

RS256, signed with a key made on the first run and kept in the user's local application-data
folder (`%LOCALAPPDATA%\DevOidc\signing-key.pem` on Windows; the path is printed at start). That
is outside every repository, so the key survives rebuilds and cannot be committed. Claims:

`iss` (the issuer, no slash at the end), `aud` (the client id), `sub` (derived from the e-mail: the
same person always gets the same value), `email`, `emails` (a list of one, as Azure AD B2C sends),
`name`, `given_name`, `family_name`, `auth_time`, `iat`, `nbf`, `exp`, and `nonce` when the sign-in
sent one.

**No roles, no groups.** DevOidc says who someone is. What they may do is the application's
business, as it should be.

Two details that are deliberate:

- **A renewed token keeps the `auth_time` of the original sign-in**, as a real provider's does.
- **One person never gets the same `auth_time` twice.** A sign-in that would fall in the same
  second as that person's previous one waits for the next second. An API that revokes a session
  by remembering the `auth_time` of the token that signed out, and then refuses every token that
  is not newer, would otherwise refuse a sign-in made right after a sign-out. A provider with a
  password to type never produces that; one with a single click does.

## Endpoints

| | |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery. |
| `GET /jwks` | The public signing key. |
| `GET /authorize` | The sign-in page. Needs `response_type=code` and PKCE (`code_challenge_method=S256`). Answers in the query, or in the fragment with `response_mode=fragment`. |
| `POST /token` | `authorization_code`, `refresh_token`, and `urn:devoidc:user` (above). |
| `GET /userinfo` | The person a bearer token belongs to. |
| `GET /logout` | End of session: revokes that person's refresh tokens when `id_token_hint` is sent, then returns to `post_logout_redirect_uri`. |

Codes, refresh tokens and the record of sign-in moments live in memory. A restart signs everyone
out; tokens already issued stay valid until they expire, because the key is the same.

## Connecting an application (MSAL.js)

```js
auth: {
  clientId: "7f1c2a9e-0000-4000-8000-000000000001",
  authority: "https://localhost:5443",
  knownAuthorities: ["localhost:5443"],   // with the port: MSAL compares host:port
  protocolMode: "OIDC",                   // or MSAL looks for Microsoft's discovery addresses
}
```

MSAL asks for the answer in the fragment and for `client_info=1`; DevOidc does both, so the rest of
the application's sign-in code runs unchanged. Keep this configuration out of anything that gets
built for a real environment.

## Connecting an API

Whatever validates JWTs from an OpenID Connect provider works: authority `https://localhost:5443`
(discovery is at `/.well-known/openid-configuration` under it), issuer `https://localhost:5443`,
audience the client id. Keep every validation on (issuer, audience, lifetime, signature): a test
provider is no reason to check less. **Load this provider on a developer's machine only.** Since
the key is made per machine and fetched from `localhost`, a token from one developer's DevOidc is
not accepted anywhere else.

## Checking it

With DevOidc running:

```
uv run --with cryptography --with truststore tests/test_devoidc.py --config path\to\my-project.json
```

41 checks from the outside: discovery, the key and the signature, the script grant and its
switches, the whole sign-in through the page with PKCE, renewal, sign-out, the refusals, CORS.

## The safeguards, in one place

- Listens on `127.0.0.1` and `::1` only; a second check refuses any caller that is not this machine.
- A redirect goes only to an address registered for the client, compared exactly. An unregistered
  one gets a page that says so, never a redirect.
- Cross-origin calls are allowed only from the origins of the registered redirect addresses.
- PKCE is required; a code works once, for a minute.
- The signing key is outside the repository; `.gitignore` refuses `*.pem`, `*.pfx`, `*.key`.
- `scratchpad/` is ignored by git: notes, logs and throw-away tests go there.

## License

[MIT](LICENSE) © Hussein Al Bayati

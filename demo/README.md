# b17s.Porta — end-to-end demo (Aspire + Keycloak + Zitadel)

A self-contained, **run-out-of-the-box** demonstration and functional-test harness for the
[`b17s.Porta`](../README.md) BFF library. One command brings up a complete BFF topology against
**two** identity providers — [Keycloak](https://www.keycloak.org/) and
[Zitadel](https://zitadel.com/) — orchestrated by [.NET Aspire](https://aspire.dev) (13.4).

## What it spins up

| Resource | Type | Purpose |
|---|---|---|
| `keycloak` | container | IdP #1. Realm + confidential client + test user imported from JSON (zero-touch). |
| `valkey` | container | Shared distributed cache (Redis-protocol). Both BFFs' `IDistributedCache` — the auth ticket / session store — so a session survives across replicas. |
| `postgres` | container | Database for Zitadel. |
| `zitadel` | container | IdP #2. First instance seeded with an admin + a machine service account. |
| `zitadel-provisioner` | project | One-shot init: creates Zitadel's OIDC app via API, writes its client id/secret to a file. |
| `backend` | project | Sample downstream API the BFF forwards to (`/weather`, `/me`). |
| `bff-keycloak` | project | The **b17s.Porta** BFF, pointed at Keycloak. |
| `bff-zitadel` | project | The **same** BFF project, pointed at Zitadel. |

Porta binds a single OIDC authority per app, so the demo runs the BFF **twice** — once per
provider — which mirrors how Porta is actually configured in production.

```
                       ┌──────────────┐
  browser ── /bff/* ──▶│ bff-keycloak │──▶ backend (/weather, /me)
                       │  (b17s.Porta)│      ▲
                       └──────┬───────┘      │ user token forwarded
                              │ OIDC  └──────┼──▶ valkey (shared session/ticket store)
                              ▼              │      ▲
                          keycloak           │      │
                                             │      │
                       ┌──────────────┐      │      │
  browser ── /bff/* ──▶│ bff-zitadel  │──────┘──────┘
                       │  (b17s.Porta)│
                       └──────┬───────┘
                              │ OIDC
                              ▼
                       zitadel ──▶ postgres
```

Both BFFs point their `IDistributedCache` at the one `valkey` container, so the auth ticket /
session store is shared — the no-sticky-sessions posture from [the HA guide](../docs/ha-deployment.md).
The demo's **Check health** button surfaces Porta's `distributed-cache` probe against it.

## Prerequisites

- **.NET 10 SDK** (the repo targets `net10.0`).
- **A container runtime** — Docker Desktop or Podman. Aspire uses it to run Keycloak, Zitadel,
  Postgres, and Valkey. *(There is no workload to install; Aspire 13 is purely NuGet-based.)*
- For the E2E tests: nothing extra — Playwright downloads its Chromium build automatically.

## Run it

From `demo/`:

```bash
# Option A: the Aspire CLI (if installed: `dotnet tool install -g aspire.cli`)
aspire run

# Option B: plain dotnet
dotnet run --project Demo.AppHost
```

The Aspire dashboard opens automatically. First run pulls the Keycloak/Zitadel/Postgres images,
so give it a minute. Once everything is green:

| URL | What |
|---|---|
| `http://127.0.0.1:5101` | BFF landing page (Keycloak) — click **Log in** |
| `http://127.0.0.1:5102` | BFF landing page (Zitadel) — click **Log in** |
| `http://127.0.0.1:8080` | Keycloak admin console (`admin` / `admin`) |
| `http://127.0.0.1:8081` | Zitadel console |

### Seeded credentials

| Provider | Username | Password |
|---|---|---|
| Keycloak (realm `porta-demo`) | `demo` | `demo` |
| Zitadel | `demo@zitadel.127.0.0.1` | `demo` |

### Endpoints exposed by each BFF

- `GET /` — server-rendered landing page showing session state + claims.
- `GET /bff/login`, `/bff/logout`, `/bff/backchannel-logout` — Porta's OIDC endpoints.
- `GET /bff/user` — the session identity as JSON (requires login).
- `GET /api/weather` — zero-code **pass-through** to the backend (public).
- `GET /api/me` — pass-through that **forwards your access token** to the backend (`BearerToken`).
- `GET /api/dashboard` — an **aggregating transformer** that fans out to `/weather` + `/me`.

## Run the functional / E2E tests

```bash
cd demo
dotnet test Demo.E2E.Tests/Demo.E2E.Tests.csproj
```

The test project uses **Aspire.Hosting.Testing** to boot the whole graph and **Playwright** to
drive real browser logins:

- `SmokeTests` — discovery docs resolve, public pass-through works, protected APIs deny anonymous.
- `KeycloakLoginTests` — full interactive login, then asserts the session + token forwarding.
- `ZitadelLoginTests` — full interactive login against the auto-provisioned Zitadel client.

> The tests need the container runtime too (they start the same AppHost).

## How the two providers are wired

**Keycloak** is fully declarative: [`Demo.AppHost/keycloak/realms/porta-demo-realm.json`](Demo.AppHost/keycloak/realms/porta-demo-realm.json)
is imported on startup via `WithRealmImport(...)`. It defines the `porta-bff` confidential client
(secret `porta-bff-secret`, redirect URI `http://127.0.0.1:5101/signin-oidc`) and the `demo` user.

**Zitadel** has no realm-import equivalent, so it is provisioned at runtime:

1. The AppHost seeds a machine **service account** via `ZITADEL_FIRSTINSTANCE_*` and tells Zitadel
   to write its JSON key to a bind-mounted folder (`demo/.zitadel`, git-ignored).
2. `Demo.ZitadelProvisioner` waits for that key + Zitadel health, authenticates with the
   JWT-profile grant, creates a project + OIDC web app (redirect `http://127.0.0.1:5102/signin-oidc`),
   and writes the generated client id/secret to `demo/.zitadel/bff-zitadel-client.json`.
3. `bff-zitadel` `WaitForCompletion`s the provisioner and layers that file over its configuration,
   so its `OidcAuth` section is complete before Porta binds it.

Each run wipes `demo/.zitadel` and starts Zitadel fresh, so provisioning is deterministic. To
reset everything, just stop and re-run the AppHost.

## Configuration notes

- Everything runs over plain **HTTP on 127.0.0.1**. The BFFs run in the **Development**
  environment — Porta's `CookieSecurityStartupCheck` deliberately refuses to boot with the relaxed
  cookie/HTTPS settings (`RequireHttpsMetadata=false`, `SecurePolicy=SameAsRequest`) in any other
  environment. **Do not copy these settings to production.**
- Host ports are pinned (`5100`–`5102`, `8080`, `8081`) so the OIDC redirect URIs registered in the
  realm/Zitadel app stay valid. If a port is busy, change it in
  [`Demo.AppHost/AppHost.cs`](Demo.AppHost/AppHost.cs) **and** the matching realm/redirect URIs.
- The Zitadel image is pinned to `latest` for convenience; pin a specific tag for reproducibility.
- The Zitadel login selectors in `ZitadelLoginTests` target the classic hosted login UI; adjust
  them if you switch to Zitadel's newer login app.

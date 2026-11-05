# Deploy: nx-baas

## Environment

Env: `NX_ADDR`, `NX_DATA`, `ACCOUNT_API`, `OPENPAK_SECRET`, `OPENPAK_ADMIN_KEY`,
`BAAS_SIGNING_KEY`, `BAAS_KID`, `NX_CA_DIR` (optional `ca.pem`/`ca.key` to sign the server cert),
`NX_INTERNAL_KEY` (the game API's `/internal` routes refuse everything without it),
`ACCOUNT_ERASE_KEY` (account erasure, below; unset: the route answers 503).

## Account erasure

`DELETE /internal/accounts/{account_id}/data` on the game-API listener (`NX_API_ADDR`, :20070,
container-network only, never routed by Traefik), `Authorization: Bearer $ACCOUNT_ERASE_KEY`.
It uses the one erase key the website finaliser sends to every service, not `X-Internal-Key`.
It deletes from baas.json (users, device accounts, NA map, friend-request ids, other users'
block/favourite/preference entries naming the erased user), invitations.json (sent and
received rows, groups), acbaa.json (profile, resources, names, island, uid moves, best friends
and requests, entries in other players' lists) and accounts.json (the projection, last), all in
Postgres (`nxbaas_docs`). The `account_deleted` core event does the same. Answers
`{"service":"nx-baas","rows":N}`; idempotent. Not touched: `harbor-devices.json` (consoles, no
account link), `pctlDevices` (console keyed, owned by nx-pctl) and error-report files.

## Required services

The eShop, Penne, parental controls and BCAT live in their own services: nx-shop, nx-penne,
nx-pctl and nx-bcat ([`docs/service-split.md`](service-split.md)). nx-baas does not serve
them, it only forwards what still reaches it, so **`NX_SHOP_URL`, `NX_PENNE_URL` and
`NX_PCTL_URL` are required**: without one the process exits at startup naming the missing
variable. `NX_BCAT_URL` is optional, because Traefik routes the bcat hosts straight to nx-bcat;
unset, any bcat request that still lands here gets `404 {}` and one log line. The services
ask this one about accounts on `/internal/identity` (game-API listener, strict
`NX_INTERNAL_KEY`).

## PlayFab forwarding

PlayFab is a separate service under `servers/playfab`. Set
`NX_PLAYFAB_URL=http://openpak-playfab:22650` to forward Core Keeper's
`94845.playfabapi.com` requests before body/debug logging. Other PlayFab titles
still receive the SDK's 503 envelope. `/internal/switch/identity` returns the
verified `application_id` when called with an `id_token`; PID/openpak lookups
do not assert application scope.

## OpenPak backend (`ACCOUNT_BACKEND=openpak`)

Identity source is the OpenPak account core over internal gRPC instead of
the earlier account server. BAAS behavior is unchanged; the Switch identifier
projection (pid, baas user id, friend code) is owned here, bound to core
accounts via `Links` (namespace `switch`).

```
ACCOUNT_BACKEND=openpak
ACCOUNT_GRPC_ADDR=127.0.0.1:7000   # account core internal gRPC
ACCOUNT_INTERNAL_KEY=…             # core fail-closed key (>=32 bytes)
WEBSITE_INTERNAL_URL=…             # website base URL; with the key below, a
WEBSITE_INTERNAL_KEY=…             # console's uploaded picture becomes the
                                   # account's avatar. Unset: kept here only.
NEX_SIGNING_KEY=…                  # openpak signing key (>=32 bytes); title
                                   # servers list this as their trusted issuer
SWITCH_NAMESPACE=switch
```

Projection store: `$NX_DATA/accounts.json` (account_id → pid/baas id/friend
code). Identifiers are minted once per account and never migrate (PRD
SW-01/SW-04). The earlier account backend stays available (`ACCOUNT_BACKEND` unset)
until cutover is accepted.

## Operations

- Everything the adapter does not recognise is logged in full (`!! UNHANDLED`); that is how
  undocumented console traffic (friend invitations, for one) gets discovered.
- Known scaling ceilings, fine for one console: `ensure` holds the global projection mutex across
  up to three core RPCs and every identity lookup takes it, so console traffic serializes on core
  latency (fix: per-account locks, mint outside the lock); `Identity` is four core RPCs per BAAS
  request with no cache (fix: a short TTL cache).
- `go.mod` uses `replace openpak/account => ../account`, so container builds need the whole
  tree as build context until the core publishes versioned modules.

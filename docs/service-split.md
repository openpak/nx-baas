# Splitting nx-baas into services

**Why.** Every nx-baas release restarts everything it serves: consoles lose their Penne push
connections and have to log in again, and a store upload of several GB dies mid-flight. The
shop changes most and holds the most data, so it goes first; Penne (push) and moon (parental
controls) follow.

**Shape (owner's decision, 2026-10-04).** Four services in four repositories, OpenPak's
per-service convention, plus one small shared module:

| repo | owns | data |
|---|---|---|
| **nx-baas** (this one) | identity core: dauth/dcert/aauth, BAAS, NA, friends, presence, invitations, bans, link pages, error reports, news/bcat, NSO/Lhub and znc pages, the vermillion gateway, capi, olsc/saves, acbaa, everything else | `baas.json`, `accounts.json`, `acbaa.json` |
| **nx-shop** | the native eShop: savanna/bugyo pages and API, store admin, atum and the d4c family, beach, dragonst, tigers, the store rights routes of dragons, pushmo/tagaya/superfly/veer/aqua/sun, bundles, idbe, bvc, pearljam | `shop/` (catalog, state, packages), `idbe/`, `pearljam/` |
| **nx-penne** | Penne: registrations (god), login tickets (val), the persistent frontline (fro-), delivery, topic and device messages | `penne.json` |
| **nx-pctl** | parental controls: moon (`api-*.pctl`), the explainer movie, `/internal/pctl` for the website | `pctl.json` |
| **nx-common** | shared Go module: `nxtls`, `nxjwt`, `nxhttp`, `internalkey`, `nxapi` (the internal contract and its client) | none |

The local directories sit beside this one (`../nx-shop`, `../nx-penne`, `../nx-pctl`,
`../nx-common`), each a git repository with no remote yet. Each service has its own `go.mod`,
binary, `Dockerfile`, tag-triggered `release.yml` (identical to this repo's: self-hosted
podman runner, multi-arch manifest to `ghcr.io/openpak/<repo>`), a sample quadlet and its
Traefik router in `deploy/`.

nx-common has no remote, so each service `replace`s it with `../nx-common` and commits
`vendor/`; the image build then needs only the service's own repository and the release
workflow stays the same as here. nx-baas does **not** import nx-common yet: it is the live
monolith another session ships to every day, and changing its build in the same branch as
the split buys nothing. Its internal routes implement the same JSON, and
`internal_identity_test.go` pins the field names. Moving nx-baas onto nx-common is a
follow-up once the cut-overs are done.

**nx-baas keeps serving everything until routing moves.** Its copies of the shop, Penne and
moon code stay, and each family only leaves it when its `NX_*_URL` is set. So production is
unchanged by deploying this branch, every cut-over is a quadlet/Traefik step, and every
rollback is the same step backwards. Deleting nx-baas's copies is the last step, after the
cut-overs have run for a while.

## 1. Dependency map

What each family reached into, read from the code at `f2cb368`.

### Shop

| shop code | reached into | after the split |
|---|---|---|
| `shopPrincipal` / `shopPrincipalUnchecked` (beach.go): NA id token → `store.PIDForNA` → `store.UserByPID`; NSA (BAAS) id token → `store.User(sub).NaID`; then `naLock` → ban cache | `baas.json`, bans | identity API `GET /internal/identity/na/{na_id}` (BAAS user, pid, lock) and `GET /internal/identity/users/{id}` (NA id, lock) |
| `idTokenAccounts` (dragonst `na_id_tokens`): BAAS id token → `store.User.NaID` | `baas.json` | `GET /internal/identity/users/{id}` |
| token verification: `bearerHeader`, `deviceIdentity` (DeviceAuthorization = dauth device token), `parseJWT(…, &s.key.PublicKey)` for NA, NSA and device tokens, issuers `naIssuer`/`baasIssuer` | `s.key` | the same BAAS key file, mounted read-only into nx-shop |
| `dragonsEdgeToken` (dragonst) / `verifyDragonsEdgeToken` (atum c2): signed with `s.key`, kid `s.idKid` | `s.key` | the same key and kid, so a token minted before the cut-over still verifies after it. Only atum reads these, so a shop-only key is possible later; not done, because it would change the token on the wire |
| `penneShopAccounts` (pushmo `/p/<penne id>`): `notifStore().AssocIfLive` + `UsersOn` → `store.User.NaID` | `penne.json`, `baas.json` | penne API `GET /internal/penne/registrations/{penne_id}`, then the users API |
| `/ashigaru/api/v1/me/avatar`: `s.baas` on `/1/<user>` | baas avatar route | `GET /internal/identity/users/{id}/avatar` (the same handler) |
| store admin `accounts/{account}/…`: `openpakBackend.proj.ByAccount` | `accounts.json` | `GET /internal/identity/accounts/{account_id}` |
| `dump`, `writeJSON`, `hostOf`, JWT and id helpers, `pageCSS`/`logoDataURI` (link.go), `footerJS` (nso.go) | helpers | nx-common, or copied page assets |
| `NX_DATA/shop`, `NX_DATA/idbe`, `NX_DATA/pearljam` | files | the shop's own; nothing else reads them |

And the other way round, nx-baas code that read the shop:

| core code | reads | after the split |
|---|---|---|
| `friendsAppCatalog`: `/v1/apps/<id>/catalog.json` and art, path-routed on **any** host (the friends module asks `c-%.accounts.nintendo.com`) | catalog, icons | forwarded to nx-shop when the shop has moved |
| `nimUnserved` `/v1/a/<id>/dv` and `/v1/acds/search` on the vermillion gateway and the catch-all | catalog | forwarded |
| dragons.\*: the dauth handler's licence answers **and** the store rights routes (`shopRightsRoute`) on one hostname | — | see "dragons" below |
| `/internal/store/*` on the game-API listener (the website's admin pages) | shop state | forwarded |

**Who owns dragons rights for Nintendo (non-store) titles after the split: nx-baas.**
Traefik routes by SNI, not by path, so `dragons.hac.lp1.dragons.nintendo.net` can have only
one owner. It carries what every title and account setup needs — `elicenses/exercise` (may
this user play online), `contents_authorization_token_for_aauth`, `elicense_archives/publish`,
`publish_device_linked_elicenses`, `migration_state`, `penne_id` — and a 404 on any of them is
2124-3121 or a game that will not go online. Those must not depend on the shop being up, so
dragons. stays on nx-baas, and nx-baas forwards only the five store rights routes
(`rights/publish_elicenses`, `rights/available_elicenses`, `elicenses/revoke`,
`edge_token/issue`, `edge_token/issuable_titles`) to nx-shop. dragonst. and tigers. are the
store's alone and route straight to nx-shop.

**NSO stays in nx-baas.** `nso.go` is the HOME Menu's Switch Online pages (Lhub), its badge
feed and the znc voice lobby. It is not commerce: it shows the account's nickname, asks the
core which OpenPak account a console is for the voice room, and talks to the website. It
shares two page scripts with the shop (`shopBridgeJS`, `footerJS`); nx-shop carries its own
copies, since page assets diverge per page anyway.

### Penne

| direction | call | after the split |
|---|---|---|
| core → penne | `BindConsole` (`/1.0.0/login`, NA token refresh) | `POST /internal/penne/consoles` |
| core → penne | `RecordPushChannel` (`/1.0.0/push_channels`) | `POST /internal/penne/push-channels` |
| core → penne | `SubmitNotification` (core friend events, presence fan-out, invitations, the test route) | `POST /internal/penne/notifications`; the core still decides recipients and visibility |
| core → penne | `deliverToTopic` (news push) | `POST /internal/penne/topic-messages` |
| core → penne | `bindTokenProfile` (olsc token upload, the saves proxy) | `POST /internal/penne/token-bindings` |
| core → penne | `penneHub.closeUser` (ban event) | `POST /internal/penne/users/{id}/close` |
| moon → penne | `pctlPush`: `AssocIDForUser(dauth id)` + every session on that registration | `POST /internal/penne/device-messages` |
| shop → penne | pushmo `/p/` | `GET /internal/penne/registrations/{penne_id}` |
| penne → core | frontline `userLock` | `GET /internal/identity/users/{id}` (lock) |
| penne → core | DAPresence → `noteClientPresence`; `renewDevicePresence` | `POST /internal/identity/presence`, `/presence/renew` |
| penne → core | online-notification policy: `prefOf(viewer, friend)` | `GET /internal/identity/users/{id}/friends/{friend}/preference` |
| penne → core | `SubmitNotification`'s "is this a user" check | stays with the caller (the core checks before it submits) |
| penne → key | bearer verification on god/val (`s.bearer`), ticket validation | the BAAS key, read-only |

The **vermillion gateway** (`gw.hac.lp1.vermillion.srv.nintendo.net`) is handled inside
`penne.go` but is not push: it is the online-licence gate and the per-title bootstrap
(`accounts/config`, vphyms, `vermillion-device-id`), stateless, and a 404 there restarts a
title's whole bootstrap. It stays in nx-baas.

### Moon (parental controls)

| moon code | reached into | after the split |
|---|---|---|
| `Store.Pctl*` | the `pctlDevices` map inside `baas.json` | its own `pctl.json`, the same `Store` type with only that field; imported once from `baas.json` |
| bearer (dauth device token) | `s.key` | the key, read-only |
| `pctlPush` | penne store + live sessions | `POST /internal/penne/device-messages` |
| `moonMii` | `WEBSITE_INTERNAL_URL` | same |
| `/internal/pctl/*` | game-API listener (the website calls it) | nx-pctl's internal listener; nx-baas forwards while the website still points at it |
| nothing in the core reads pctl data | | |

### Shared, per file

`$NX_DATA` today holds `baas.json` (users, devices, NA map, friend requests, **pctl
devices**), `accounts.json` (core account projection), `acbaa.json`, `penne.json`, `shop/`,
`idbe/`, `pearljam/`, `default.jpg`, and maybe `ca/`. After the split each file has exactly
one writer: the core keeps the first three, nx-penne `penne.json`, nx-pctl `pctl.json`,
nx-shop `shop/`, `idbe/`, `pearljam/`.

## 2. Internal API

Plain HTTP on the `openpak` network, `X-Internal-Key: $NX_INTERNAL_KEY` (or
`OPENPAK_INTERNAL_KEY`), **strict**: no key configured means 503 for everyone, like the store
admin API, because these answers map accounts to each other. JSON shapes are
`nx-common/nxapi`'s; a caller treats an unreachable peer as "unknown", logs it, and degrades
that one request.

Identity, served by nx-baas on `NX_API_ADDR` (`:20070`):

| route | answer |
|---|---|
| `GET /internal/identity/users/{baas_user_id}` | `{id, na_id, pid, nickname, lock}`; 404 unknown |
| `GET /internal/identity/users/{id}/avatar` | the image `/1/{id}` serves on the cdn-image host |
| `GET /internal/identity/users/{id}/friends/{friend}/preference` | `{online_notification}` |
| `GET /internal/identity/na/{na_id}` | `{na_id, baas_user_id, pid, lock}`; an NA id no console linked is 200 with an empty `baas_user_id` |
| `GET /internal/identity/accounts/{account_id}` | `{account_id, na_id}`; 404 without the openpak backend or a projection |
| `POST /internal/identity/presence` | `{user_id, device, state, app_id, app_field, group_id, acd_index}` → 204; recorded as the console's (`client=switch`) |
| `POST /internal/identity/presence/renew` | `{user_id, device}` → 204 |

Penne, served by whoever holds the push state — nx-baas until the Penne cut-over, nx-penne
after; nx-baas forwards `/internal/penne/*` once Penne has moved, so a caller pointed at the
core keeps working:

| route | answer |
|---|---|
| `GET /internal/penne/registrations/{penne_id}` | `{penne_id, live, user_id, users}` |
| `POST /internal/penne/consoles` | `{device_id, user_id}` → 204 |
| `POST /internal/penne/push-channels` | `{user_id, device_account_id, service, device_token}` → 204 |
| `POST /internal/penne/notifications` | `{id, user_id, kind, payload}` → `{accepted, duplicate, outcome, id}` |
| `POST /internal/penne/topic-messages` | `{topic, name, receivers, body}` → `{subscribers, delivered}` |
| `POST /internal/penne/token-bindings` | `{notification_token, user_id}` → `{bound}` |
| `POST /internal/penne/users/{id}/close` | → `{closed}` |
| `POST /internal/penne/device-messages` | `{penne_id \| dauth_user, name, receivers, body}` → `{penne_id, connections}` |

The shop and moon need nothing new from the website; nx-pctl keeps calling
`WEBSITE_INTERNAL_URL` for the parent's picture exactly as nx-baas did.

## 3. TLS and hostnames

Traefik's `console` entrypoint is TCP with `tls: passthrough`: it reads the SNI and splices.
Each moved family gets one TCP router listing its hostnames (`deploy/traefik-nx-*.yml` in each
repo), above the `HostSNI(*)` catch-all that sends everything else to nx-baas. The new service
terminates TLS itself with `nx-common/nxtls`, which is nx-baas's listener code unchanged: a
fixed multi-SAN certificate signed by the OpenPak CA for the names that were on nx-baas's
fixed certificate (the console refuses an on-demand certificate on names it authenticates
strictly, 2123-0013), on-demand CA-signed certificates for every other SNI, all cipher suites
from TLS 1.0, and no client-certificate request. So each service mounts the CA directory
(`NX_CA_DIR`) read-only. Client certificates stay a dauth/dcert/aauth affair, which stay in
nx-baas.

**nx-baas forwards whatever of a moved family still reaches it** (`split.go`): with
`NX_SHOP_URL` set, every eShop host that lands on the catch-all, the path-routed catalog
requests and `/internal/store/*` go to nx-shop's internal listener over plain HTTP with the
console's Host kept. That makes the Traefik router an optimisation rather than a
precondition: a store hostname nobody listed still works, through nx-baas. The exception is
Penne's frontline (fro-), a full-duplex stream nx-baas cannot proxy (net/http drains the
request body on the first flush, which is why the frontline hijacks); nx-baas answers 421 for
it once Penne has moved, so the Penne router must be in place at the cut-over.

A service asked for a hostname it does not own answers **421** and logs `!! MISROUTED`, never
another family's handler.

Forwarded console traffic never reaches an admin route. nx-baas refuses any `/internal/` path
on a moved family's hostname before forwarding, and each service's internal listener sends a
request naming a Nintendo host straight to its console handler — never through the ServeMux
holding `/internal/*` (nx-common `nxhttp.SplitListener`), which also spares forwarded paths
the ServeMux's 301 path cleaning. Only a request naming the service itself
(`openpak-nx-shop:20070` and the like) reaches `/internal/*`.

## 4. Order, risk, and what to re-verify on hardware

**Shop first.** Lowest blast radius (a shop outage stops the store and nothing else), most
churn, most data. Risks: an identity call shape mismatch (pinned by tests on both sides);
the data directory being written by two processes (prevented by the order below); a store
name Traefik does not list (covered by nx-baas's forward). Re-verify on the console, end to
end, the chain that works today:

1. open the shop: savanna catalog renders, the avatar shows top right (identity API);
2. acquire a title, `POST /tasks` (principal through `/internal/identity/na`);
3. `requestSyncRights`: dragons `rights/publish_elicenses` on **dragons.** (nx-baas → nx-shop
   forward) accepts the rights id;
4. aqua `required_system_update_meta`, then pushmo `/p/<penne id>` lists the task (penne
   registrations API through nx-baas);
5. superfly `dv`, veer policy;
6. atum HEAD/GET of the CNMT with `x-nintendo-title-version/content-id/content-hash`;
7. dragonst `issuable_titles` and `issue` with `na_id_tokens` (BAAS id tokens map through the
   users API);
8. atum c2 program content with the bare `DenebEdgeToken`; the title installs and launches;
9. a non-store title still launches and goes online (dragons. exercise stayed on nx-baas);
10. the website's store admin: list, upload a version, publish (forwarded through nx-baas,
    then direct once the website points at nx-shop).

**Penne second.** The highest-value move — push connections survive core releases — and the
most delicate: it has the long-lived connections, and the core feeds it from four places.
Risks: the few seconds between the core restart and nx-penne's start (the core's queue
retries each push for up to a minute, in order, so nothing it submits in that gap is lost;
the outbox itself moves with `penne.json`);
consoles holding tickets for the old process (they are imported with `penne.json`); the
frontline router missing (consoles cannot connect; 421 in the core's log). Re-verify: a
console's frontline connects and stays up across an nx-baas restart; a friend request, accept
and removal each arrive as a notification; presence (DAPresence) shows on a friend's list and
stays (renewal); an invitation arrives; a news push reaches a subscribed console; a banned
account's frontline is closed.

**Moon last.** Smallest and least used. Risks: the one-time import of `pctlDevices` from
`baas.json`; the parent app pointing at nx-baas (forwarded until it is repointed).
Re-verify: pair a console with a code, change a setting in the app and see the console fetch
it at once (the push through nx-penne), the parent's picture shows, unlink.

## 5. Shop cut-over runbook

Nothing below is applied by this branch. Paths in `<…>` are the ones `openpak-nx-baas.container`
already uses on the box; read it first (`systemctl --user cat openpak-nx-baas`).

**Preconditions.** This branch merged and released (the nx-baas image carries the identity
API and the forwarders; with no `NX_*_URL` set it behaves exactly as before — verify that
after the release: `curl -sk --resolve m-lp1.baas.nintendo.com:21443:127.0.0.1
https://m-lp1.baas.nintendo.com:21443/healthz` and open the shop once). `ghcr.io/openpak/nx-shop`
published from nx-shop's first tag. `NX_INTERNAL_KEY` present in `~/openpak/deploy/.env`.

1. **Install the quadlet, do not start it.** Copy `nx-shop/deploy/openpak-nx-shop.container` to
   `~/.config/containers/systemd/`, fill in the two host paths: the store directory is
   `<nx-baas data dir>/shop` itself (no copy, no move), and the keys directory nx-baas mounts.
   `systemctl --user daemon-reload`. `podman pull ghcr.io/openpak/nx-shop:latest`.
2. **Switch nx-baas to forwarding.** Add `NX_SHOP_URL=http://openpak-nx-shop:20070` to
   `~/openpak/deploy/.env` (no other service reads it). `systemctl --user restart
   openpak-nx-baas` (restart, not stop/start: Photon, MHGU, Splatoon 3 and Traefik
   `Require=` it). From here nx-baas no longer reads or writes `shop/`; shop requests get
   502 from it for the next few seconds.
3. **Start nx-shop.** `systemctl --user start openpak-nx-shop`. It loads `shop/` now that nobody
   else writes it. Check `journalctl --user -u openpak-nx-shop` for `titles=<n>` and the CA
   line (`server cert signed by the OpenPak CA`).
4. **DNS sanity** (the aardvark lesson): `podman exec openpak-traefik getent hosts
   openpak-nx-shop` and `podman exec openpak-nx-baas getent hosts openpak-nx-shop` must match
   `podman inspect openpak-nx-shop`; after the nx-baas restart re-check `openpak-nx-baas` the
   same way (kill aardvark + `podman network reload --all` if stale).
5. **Smoke through nx-baas** (the forward):
   `curl -sk --resolve hac.lp1.savanna.srv.nintendo.net:21443:127.0.0.1
   https://hac.lp1.savanna.srv.nintendo.net:21443/top | grep -c 'OpenPak Shop'` and
   `curl -sk --resolve superfly.hac.lp1.d4c.nintendo.net:21443:127.0.0.1
   https://superfly.hac.lp1.d4c.nintendo.net:21443/v1/a/<a catalog title id>/dv`.
   Both appear in nx-shop's journal.
6. **Take nx-baas out of the path.** Merge `nx-shop/deploy/traefik-nx-shop.yml` into
   `~/openpak/deploy/traefik/dynamic.yml` (back up to `~/openpak/deploy/traefik/` — never
   into the aardvark directory). Traefik reloads the file by itself; repeat step 5 and see the
   requests in nx-shop's journal and **not** in nx-baas's.
7. **Point the website's store admin at nx-shop** when convenient (its nx-baas base URL →
   `http://openpak-nx-shop:20070`); until then nx-baas forwards `/internal/store/*`,
   uploads included (streamed).
8. **Hardware**: the ten checks in §4.

Optional, any time later: move the store directory into nx-shop's own volume (stop nx-shop,
`mv`, change its `Volume=`, start it). nx-baas is not involved.

**Rollback** (any step): remove the `nx-shop` router from `dynamic.yml`;
`systemctl --user stop openpak-nx-shop` (one writer at a time); remove `NX_SHOP_URL` from the
`.env`; `systemctl --user restart openpak-nx-baas`, which loads `shop/` again with everything
nx-shop wrote — the directory never moved. The website's admin URL goes back to nx-baas if it
was changed.

**After a few quiet weeks**: drop nx-baas's shop files (shop.go, shop_data.go,
store_admin.go, atum.go, beach.go, eshop_*.go except the parts the core keeps) and its shop
names from the fixed certificate. Until then, shop fixes land in nx-shop; nx-shop's README
says how to port one that landed in nx-baas first.

## 6. Penne cut-over runbook

Penne is the one move with a short outage on purpose: `penne.json` is a single file with one
writer, so nx-baas stops writing it before nx-penne starts from it. Consoles lose their
frontline for the seconds in between, exactly as they do on every nx-baas restart today —
and that is the last time a core release costs them their connection.

**Preconditions.** The shop cut-over done (not required, but one move at a time). This
branch released. `ghcr.io/openpak/nx-penne` published. Know the host path of nx-baas's data
directory (`/app/data` in the container; `penne.json` is in it).

1. **Install the quadlet, do not start it.** Copy `nx-penne/deploy/openpak-nx-penne.container`
   to `~/.config/containers/systemd/`, fill in nx-baas's data directory (mounted read-only at
   `/import`, read once) and the keys directory. `systemctl --user daemon-reload`;
   `podman pull ghcr.io/openpak/nx-penne:latest`.
2. **Route the frontline first.** Merge `nx-penne/deploy/traefik-nx-penne.yml` into
   `dynamic.yml` (backup outside the aardvark directory). From here consoles' Penne
   connections fail until step 4 — seconds.
3. **Switch nx-baas.** Add `NX_PENNE_URL=http://openpak-nx-penne:20070` to
   `~/openpak/deploy/.env`; `systemctl --user restart openpak-nx-baas`. It no longer opens
   `penne.json` and sends every push to nx-penne (queued, so its logins never wait on it).
4. **Start nx-penne.** `systemctl --user start openpak-nx-penne`. The journal must show
   `imported /import/penne.json (… bytes) as /app/data/penne.json`. nx-penne imports whenever
   nx-baas's file is not the one it last imported (it keeps the fingerprint in
   `penne.json.imported`), so a **second cut-over after a rollback** takes nx-baas's current
   state by itself and sets its own stale copy aside as `penne.json.before-import-<time>`.
   Belt and braces for that case: before step 4, `podman volume rm openpak-nx-penne-data`
   (nothing in it is newer than what the rollback handed back).
5. **DNS sanity** for `openpak-nx-penne` (from Traefik and from nx-baas) and again for
   `openpak-nx-baas` after its restart.
6. **Smoke.** `curl -sk --resolve val.hac.lp1.penne.srv.nintendo.net:21443:127.0.0.1 -X POST
   https://val.hac.lp1.penne.srv.nintendo.net:21443/v1/frontlines` answers with
   `frontline_fqdn` from nx-penne's journal. A console reconnects within its retry interval:
   `penne frontline: open user=…` in nx-penne's journal. `curl -s -H "X-Internal-Key: $KEY"
   -X POST -d '{"user_id":"<a console user>","kind":"friend_deleted","id":"probe-1"}'
   http://openpak-nx-baas:20070/internal/notifications/test` (from a container on the
   network) reports `persisted` from nx-penne.
7. **Point nx-shop straight at nx-penne** (optional: nx-baas forwards `/internal/penne/*`):
   `NX_PENNE_URL` in the `.env` already does it; `systemctl --user restart openpak-nx-shop`.
8. **Hardware**: §4's Penne list, and the one that motivated the move — restart nx-baas
   (`systemctl --user restart openpak-nx-baas`) and watch the console's connection in
   nx-penne's journal stay open.

**Rollback**: remove the `nx-penne` router; `systemctl --user stop openpak-nx-penne`; copy its
state back over nx-baas's — `podman cp openpak-nx-penne:/app/data/penne.json
~/openpak/penne-rollback.json` (works on a stopped container), then `podman unshare cp` it over
`penne.json` in nx-baas's data directory and `podman unshare chown 65532:65532` it, as the
original was; remove `NX_PENNE_URL` from the `.env`; `systemctl --user restart
openpak-nx-baas`. Notifications submitted while nx-penne was down are lost; consoles
reconnect to nx-baas.

Day to day after the move: restarting nx-penne costs consoles their connection (they
reconnect) and nothing else; the core holds its pushes for up to a minute meanwhile, in
order. That minute is one budget shared by the whole queue: past it nx-penne counts as down,
queued pushes are dropped at once (each logged) with one probe every five seconds, and the
first push it takes again ends the outage. A 501, or nx-penne saying it has no internal key,
is a deployment fault and never retried.
Restarting nx-baas costs consoles nothing on Penne.

**Later**: drop nx-baas's Penne files except what the core keeps (the vermillion gateway,
`penne_link.go`), its Penne names from the fixed certificate, and the `/import` mount from
nx-penne's quadlet.

## 7. Parental controls cut-over runbook

The records live inside `baas.json` today, which only nx-baas writes, so the order is: nx-baas
stops serving parental controls, then nx-pctl takes the records out of `baas.json` as they
stand. A console polling its setting in the seconds between gets a 502 and polls again later.

**Preconditions.** This branch released; `ghcr.io/openpak/nx-pctl` published. Penne moved
first is not required: without `NX_PENNE_URL` nx-pctl pushes through nx-baas
(`NX_CORE_URL`), which serves or forwards the penne API either way.

1. **Install the quadlet, do not start it** (`nx-pctl/deploy/openpak-nx-pctl.container`): fill
   in nx-baas's data directory (read-only at `/import`, read once), the keys directory, and
   the `PCTL_MOVIE` mount if nx-baas has one. `systemctl --user daemon-reload`;
   `podman pull ghcr.io/openpak/nx-pctl:latest`.
2. **Switch nx-baas.** Add `NX_PCTL_URL=http://openpak-nx-pctl:20070` to the `.env`;
   `systemctl --user restart openpak-nx-baas`. It forwards the pctl hosts and
   `/internal/pctl` from now on and no longer changes the records in `baas.json`.
3. **Start nx-pctl.** `systemctl --user start openpak-nx-pctl`; the journal must show
   `imported <n> parental-controls record(s) from /import/baas.json`. As with Penne, nx-pctl
   imports whenever the records in `baas.json` are not the ones it last imported (fingerprint
   of the `pctlDevices` value in `pctl.json.imported`; the rest of `baas.json` changes on every
   login and is ignored), so a **second cut-over after a rollback** takes nx-baas's records and
   sets its stale copy aside as `pctl.json.before-import-<time>`. Belt and braces: before this
   step on a second cut-over, `podman volume rm openpak-nx-pctl-data`.
4. **DNS sanity** for `openpak-nx-pctl` and, after its restart, `openpak-nx-baas`.
5. **Smoke.** `curl -sk --resolve api-lp1.pctl.srv.nintendo.net:21443:127.0.0.1
   'https://api-lp1.pctl.srv.nintendo.net:21443/moon/v1/devices?filter.links.pairingCode.code.$eq=000000'`
   answers `{"items":[]}` from nx-pctl's journal; the website's parental-controls page lists
   the paired consoles (forwarded through nx-baas).
6. **Take nx-baas out of the path**: merge `nx-pctl/deploy/traefik-nx-pctl.yml`; point the
   website's parental-controls base URL at `http://openpak-nx-pctl:20070` when convenient.
7. **Hardware**: §4's moon list.

**Rollback**: remove the `nx-pctl` router; `systemctl --user stop openpak-nx-pctl`; copy its
records back for nx-baas to take: `podman cp openpak-nx-pctl:/app/data/pctl.json
~/openpak/pctl-rollback.json`, then `podman unshare cp` it into nx-baas's data directory as
`pctl-rollback.json` (`podman unshare chown 65532:65532`); remove `NX_PCTL_URL` from the `.env`;
`systemctl --user restart openpak-nx-baas`. On start it replaces the records in `baas.json` with
the file's and renames it `pctl-rollback.json.applied-<time>`, so the next restart does not
apply it again. It applies only a file holding exactly a `pctlDevices` object (nx-pctl writes
`{}` there when it has no records); anything else is refused with a log line and left in
place, and the records are untouched — check for `taken back from nx-pctl` in the journal.

**Later**: drop `moon.go` and the `pctlDevices` key from nx-baas (a store written with the key
still loads in an nx-baas that no longer has it), the pctl name from its fixed certificate,
and the `/import` mount from nx-pctl's quadlet.

## 8. nx-baas after all three

| env | effect |
|---|---|
| `NX_SHOP_URL` | eShop hosts, `/v1/apps/` catalog paths, superfly `dv` and acds search on kept hosts, dragons. store rights routes, `/internal/store/*` → nx-shop; `shop/` not opened |
| `NX_PENNE_URL` | god/val → nx-penne, fro- → 421, `/internal/penne/*` → nx-penne, every core push through `penne_link.go`; `penne.json` not opened, no sweeper |
| `NX_PCTL_URL` | pctl and movie hosts, `/internal/pctl/*` → nx-pctl |
| (always) | `/internal/identity/*` for the services; `pctl-rollback.json` taken on start if present |

The services find nx-baas with `NX_CORE_URL=http://openpak-nx-baas:20070`; put
`NX_SHOP_URL`, `NX_PENNE_URL`, `NX_PCTL_URL` in the shared `.env` so every process sees one
topology (only nx-baas acts on the first and third; nx-shop and nx-pctl use the second to
reach nx-penne directly).

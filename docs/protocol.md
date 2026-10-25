# Protocol: nx-baas

## Endpoints

Endpoints: `/1.0.0/application/token`, `/1.0.0/users` (+`/<id>`, `/<id>/link`, `generate_code`,
`device_accounts` presence patch), `/1.0.0/login`, `/1.0.0/federation`, `/1.0.0/certificates`,
`/2.0.0/users/<id>/friends`, `/2.0.0/friend_requests`, and the Nintendo-Account link flow
(`/connect/1.0.0/authorize`, `api/session_token`, `api/token`, `/2.0.0/users/me`).
The native invitation surface (`app.lp1.five.nintendo.net`) and its lifecycle contract live in
[`docs/invitations.md`](invitations.md).

## Linking a console

Six-digit codes, shown on the console as `123 456`, ten minutes, single use. Digits only so the
phone gets a numeric keypad and no letter can be mistaken for a digit; the generator uses
rejection sampling because 256 is not a multiple of 10.

Six digits is one in a million, so **guesses are capped**: ten wrong codes per account buys a
ten-minute wait, keyed by the account rather than the session cookie. A code alone still cannot
finish a link — the person at the console approves. Password guesses on the sign-in forms are
capped the same way (ten per account per ten minutes).

Two-factor accounts do not dead-end here: a correct password returns the account as
second-factor-owed, and the next page asks for the authenticator code (or a recovery code) —
on the phone flow (`/link/2fa`) and on the console authorize form
(`/connect/1.0.0/authorize/2fa`) alike. The pending record holds only the account id and
where to continue, never the password; it is single-use and ten minutes. This needs
`ACCOUNT_BACKEND=openpak`: the earlier account server speaks no second factor.

The console page and the phone pages share one stylesheet split by a body class: a television
read from a sofa and driven by a stick is not a phone held at arm's length. Both carry their CSS
inline, because a console browser may have no route to the website. Full flow:
internal research notes.

`PREVIEW_DIR=/tmp/link go test -count=1 -run DumpLinkPages .` writes every one of those pages out
to look at; the console page must be judged at 1280×720.

## Friends

Two rules from it, because breaking either costs an evening:

- **Every list is `{"count":n,"etag":…,"items":[…],"itemsPerPage":n}`.** Naming the array after
  its contents makes a console report "unable to find user" or show nothing at all while the data
  sits in the reply. `testdata/accepted-search-shape.json` is a capture with the values stripped,
  and the shape test compares against it — including inside `extras`, which is where four invented
  keys hid.
- **Answer in the console's own words.** It PATCHes a friend request to `AUTHORIZED`; replying
  `ACCEPTED` is "a communication error has occurred" even though the friendship committed. Since
  the console keeps its friend list locally and only writes it on an accept it believes, a reply it
  cannot read means the friendship exists on the server and nowhere else.

## The reply the console parses

`2124-3121` means the console could not parse a body, and it says nothing else — no field, no
log. `testdata/accepted-login-shape.json` holds the keys and types of a reply a console
accepted, values stripped, and `TestLoginReplyMatchesTheShapeAConsoleAccepts` drives the real
login endpoint against it. Add a key, drop a key, and that test tells you before a console does.

**Do not serve a profile blob the console did not upload.** `extras.self.nxAccount` comes from
the console's own `PATCH`; a foreign blob makes it drop the profile to local-only. The evidence
that "every account gets the same blob" is circular — that capture was our own constant coming
back from our own VPS.

## Game API (`NX_API_ADDR`, default `:20070`)


Plain HTTP on an internal port — consoles never reach it; the Photon server, the
emulator and rig tooling do. It is what those callers used to get from
the earlier account server.

| Endpoint | Caller | Notes |
| --- | --- | --- |
| `POST /internal/photon-room` `{identity,room,app_id}` | Photon | `identity` is `nex:<openpak token>` or `bsdid:<bs:did>`, straight from the client's id_token; this server resolves it. The room becomes the player's friend presence (`app_field` = the title's own application parameter). |
| `POST /internal/mint-token` `{pid}` | rig tooling | A bearer for any PID the backend knows, no password. Dev convenience. |
| `POST /internal/news/push` `{topic_id,revision[,wait_range,subscription]}` | news service | nx-penne writes `{"type":"news",…}` to every live Penne connection subscribed to the topic (raw subscribed string). Live only; see `internal/penne/news.go`. |
| `/internal/store/*`, `/internal/pctl/*`, `/internal/penne/*` | website, split-out services | Forwarded to nx-shop, nx-pctl and nx-penne, which own them. |
| `GET/POST /api/invitations` | emulator, console | Friend-invitation mailbox: opaque app-parameter bytes in, popped by the target. TTL 5 min, 8 queued per target, senders limited to their own friends. |

`X-Internal-Key` must match `NX_INTERNAL_KEY` (or `OPENPAK_INTERNAL_KEY`); with no key
configured every `/internal` route refuses (`NX_INTERNAL_INSECURE=1` opens them for isolated
development only, never production);
`/api/*` uses the `nx2.` openpak bearer. Any other `/api/*` path is forwarded to
`ACCOUNT_API` until the OpenPak core serves friends/presence/saves itself.

## Switch Online and News

`*.nso.nintendo.net` serves the HOME Menu's Switch Online page (Lhub, any path, the paywall
`launch?from=paywall…` included): membership is always active, Expansion Pack too, because
OpenPak sells nothing. `fw-api.<env>.nso.nintendo.net/v1/events` answers an empty list and
logs the request. The News channel and native game BCAT are nx-bcat's: the bcat hosts reach
it through Traefik (or `NX_BCAT_URL`). What stays here is the push that tells consoles a
topic changed (`/internal/news/push`, through nx-penne).

## Native OpenPak store

The store is nx-shop's: the shop applet's hosts, NIM's download and update hosts, beach,
dragonst, tigers, the d4c content hosts and the store admin API (`/internal/store/*`). nx-baas
forwards whatever of it still reaches it, keeps dragons' licence answers every title needs
(only its store rights routes move), and forwards the path-routed catalog questions (superfly
`dv`, acds search, the friends module's app catalog). The design notes stay in
[`docs/native-shop.md`](native-shop.md).

## Console error reports

eupld's uploads to `receive.hac.<env>.er.srv.nintendo.net/` are kept raw in
`$NX_DATA/error-reports/raw/` (pruned after `NX_ERROR_REPORT_KEEP_DAYS`, default 30),
decoded (msgpack fields, attachment) and forwarded to
`${WEBSITE_INTERNAL_URL}/api/v1/internal/crash-reports` with `X-Internal-Key:
${WEBSITE_INTERNAL_KEY}`; unsent ones wait in `error-reports/spool/` and retry every
minute. Body cap `NX_ERROR_REPORT_MAX_BYTES` (16 MiB). `internal/services/errorreport.go`.

## Bans

A core account that is banned (or deleted / pending deletion) is refused everywhere this
adapter answers, in each client's own error shape: BaaS `403 banned_user` (2124-5110),
NA `invalid_grant`/`user_banned`, game API `403 {"error":"account_banned"}` (never 401).
The core's `GetAccount` status is cached `NX_BAN_CACHE_SECONDS` (default 30, max 60) and
dropped on the core's ban/unban events. `internal/bans` lists every surface.

## Latest version only

aauth refuses a title older than its latest update with HTTP 400 code `0111`, which the
console shows as 2124-3001 "A software update is required" (Restart / Later). No download is
forced: the version list is untouched. The table is blawar/titledb's `versions.json`
(`NX_VERSION_GATE_URL`), refetched every 24 h and cached in `$NX_DATA/title-versions.json`;
a failed fetch keeps the last good table. Unknown titles and versions that are not 8 hex
digits are allowed. `NX_VERSION_GATE=0` turns it off; `NX_VERSION_GATE_OVERRIDES` takes
`<title id>=<%08x minimum>` or `<title id>=all`, comma-separated. `internal/dauth/versiongate.go`.

Game servers ask the same table on the internal API, so their own refusals (NEX
ApplicationVersionIsOld, NPLN FAILED_PRECONDITION, ...) match aauth's:
`GET /internal/title-version?title=<16 hex>&version=<id_token nintendo.av>` answers
`{"title","version","latest","update_required"}`; `latest` is empty when no minimum applies.
Callers treat any failure as allowed.

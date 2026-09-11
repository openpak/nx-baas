# nx-baas

BAAS (`*.baas.nintendo.com`) and Nintendo Account (`accounts.nintendo.com`) servers for a real
CFW Switch on the earlier stack. Backed by `openpak-account` (`/internal/*`) for identity,
friend codes and the friend graph; signs the same `openpak-baas-key-1` id_tokens the emulators
use, with the `openpak` claim, so Photon / NPLN / NEX servers see one identity per account.

Endpoints: `/1.0.0/application/token`, `/1.0.0/users` (+`/<id>`, `/<id>/link`, `generate_code`,
`device_accounts` presence patch), `/1.0.0/login`, `/1.0.0/federation`, `/1.0.0/certificates`,
`/2.0.0/users/<id>/friends`, `/2.0.0/friend_requests`, and the Nintendo-Account link flow
(`/connect/1.0.0/authorize`, `api/session_token`, `api/token`, `/2.0.0/users/me`).
The native invitation surface (`app.lp1.five.nintendo.net`) and its lifecycle contract live in
[`docs/invitations.md`](docs/invitations.md).
Everything unknown is logged in full (`!! UNHANDLED`), which is how the undocumented parts
(friend invitations) get discovered.

Env: `NX_ADDR`, `NX_DATA`, `ACCOUNT_API`, `OPENPAK_SECRET`, `OPENPAK_ADMIN_KEY`,
`BAAS_SIGNING_KEY`, `BAAS_KID`, `NX_CA_DIR` (optional `ca.pem`/`ca.key` to sign the server cert).

## OpenPak backend (`ACCOUNT_BACKEND=openpak`)

Identity source is the OpenPak account core over internal gRPC instead of
`openpak-account`. BAAS behavior is unchanged; the Switch identifier
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
SW-01/SW-04). The earlier path stays available (`ACCOUNT_BACKEND` unset)
until cutover is accepted.

## Linking a console

Six-digit codes, shown on the console as `123 456`, ten minutes, single use. Digits only so the
phone gets a numeric keypad and no letter can be mistaken for a digit; the generator uses
rejection sampling because 256 is not a multiple of 10.

Six digits is one in a million, so **guesses are capped**: ten wrong codes per account buys a
ten-minute wait, keyed by the account rather than the session cookie. A code alone still cannot
finish a link — the person at the console approves.

The console page and the phone pages share one stylesheet split by a body class: a television
read from a sofa and driven by a stick is not a phone held at arm's length. Both carry their CSS
inline, because a console browser may have no route to the website. Full flow:
[`../docs/switch/console-link-flow.md`](../docs/switch/console-link-flow.md).

`PREVIEW_DIR=/tmp/link go test -count=1 -run DumpLinkPages .` writes every one of those pages out
to look at; the console page must be judged at 1280×720.

## Friends

Adding a friend works end to end on hardware except the console's own friend list, which stays
empty; the whole investigation, every captured shape and every fix, is in
[`../docs/switch/friend-flow-2026-09-08.md`](../docs/switch/friend-flow-2026-09-08.md).

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

Two things it has caught, both self-inflicted: an extra top-level `summary` key, and a thumbnail
still saying `/1/default` after the console had uploaded a picture.

**Do not serve a profile blob the console did not upload.** `extras.self.nxAccount` comes from
the console's own `PATCH`; a foreign blob makes it drop the profile to local-only. The evidence
that "every account gets the same blob" is circular — that capture was our own constant coming
back from our own VPS.

## Game API (`NX_API_ADDR`, default `:20070`)


Plain HTTP on an internal port — consoles never reach it; the Photon server, the
emulator and rig tooling do. It is what those callers used to get from
openpak-account.

| Endpoint | Caller | Notes |
| --- | --- | --- |
| `POST /internal/photon-room` `{identity,room,app_id}` | Photon | `identity` is `nex:<openpak token>` or `bsdid:<bs:did>`, straight from the client's id_token; this server resolves it. The room becomes the player's friend presence (`app_field` = the title's own application parameter). |
| `POST /internal/mint-token` `{pid}` | rig tooling | A bearer for any PID the backend knows, no password. Dev convenience. |
| `GET/POST /api/invitations` | emulator, console | Friend-invitation mailbox: opaque app-parameter bytes in, popped by the target. TTL 5 min, 8 queued per target, senders limited to their own friends. |

`X-Internal-Key` must match `NX_INTERNAL_KEY` (or `OPENPAK_INTERNAL_KEY`) when set;
`/api/*` uses the `nx2.` openpak bearer. Any other `/api/*` path is forwarded to
`ACCOUNT_API` until the OpenPak core serves friends/presence/saves itself.

## Known scaling ceilings (recorded, fine for one console)

- `ensure` holds the global projection mutex across up to three core RPCs,
  and every identity lookup takes that mutex: console traffic serializes on
  core latency. Fix when a second console lands: per-account locks, mint
  outside the lock.
- `Identity` is four core RPCs per BAAS request with no cache. Add a short
  TTL cache when traffic grows.
- `go.mod` uses `replace openpak/account => ../account`, so container builds
  need the whole `Openpak/` tree as build context until the core publishes
  versioned modules.

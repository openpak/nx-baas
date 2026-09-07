# nx-baas

BAAS (`*.baas.nintendo.com`) and Nintendo Account (`accounts.nintendo.com`) servers for a real
CFW Switch on the earlier stack. Backed by `openpak-account` (`/internal/*`) for identity,
friend codes and the friend graph; signs the same `openpak-baas-key-1` id_tokens the emulators
use, with the `openpak` claim, so Photon / NPLN / NEX servers see one identity per account.

Endpoints: `/1.0.0/application/token`, `/1.0.0/users` (+`/<id>`, `/<id>/link`, `generate_code`,
`device_accounts` presence patch), `/1.0.0/login`, `/1.0.0/federation`, `/1.0.0/certificates`,
`/2.0.0/users/<id>/friends`, `/2.0.0/friend_requests`, and the Nintendo-Account link flow
(`/connect/1.0.0/authorize`, `api/session_token`, `api/token`, `/2.0.0/users/me`).
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
NEX_SIGNING_KEY=…                  # openpak signing key (>=32 bytes); title
                                   # servers list this as their trusted issuer
SWITCH_NAMESPACE=switch
```

Projection store: `$NX_DATA/accounts.json` (account_id → pid/baas id/friend
code). Identifiers are minted once per account and never migrate (PRD
SW-01/SW-04). The earlier path stays available (`ACCOUNT_BACKEND` unset)
until cutover is accepted.

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

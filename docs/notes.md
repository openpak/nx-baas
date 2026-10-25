# Notes: nx-baas

## Overview

BAAS (`*.baas.nintendo.com`) and Nintendo Account (`accounts.nintendo.com`) servers for a real
CFW Switch. Backed by the earlier account server (`/internal/*`) for identity,
friend codes and the friend graph; signs the same `openpak-baas-key-1` id_tokens the emulators
use, with the `openpak` claim, so Photon / NPLN / NEX servers see one identity per account.

## Code layout

One binary, one `package main` that only wires and routes (`main.go`, `routes.go`, `split.go`
for the forwarders, `proxy.go` for capture mode), and the surfaces under `internal/`:

| package | what |
| --- | --- |
| `core` | the shared state every surface holds: the BAAS store, the account backend, the signing key, the Harbor registry, the nx-penne client and the forwarders, plus the bearer checks |
| `dauth` | dauth, dcert and aauth: device, edge and application tokens, the latest-version gate |
| `devices` | Harbor device enrolment (`harbor-devices.json`) |
| `baas` | application token, login, users, federation, certificates, the avatar host |
| `nxaccount` | the Nintendo Account link flow (authorize, session_token, token, users/me) and the link pages |
| `friends` | friends, friend requests, relationships, blocks, and the BAAS user/friend objects |
| `presence` | per-device presence, the aggregate friends see, the core's sessions, other platforms |
| `invitations` | the five host and the invitation mailbox (`invitations.json`) |
| `identity` | the account backends and the Switch projection: PID / BAAS id / friend code to core account (`accounts.json`) |
| `bans` | the ban check and each surface's refusal |
| `penne` | the core's client of nx-penne: the ordered push queue, notifications, the news push |
| `events` | the account core's event follower: bans, deletions, friendships, presence elsewhere |
| `gameapi` | the game-facing internal API (`NX_API_ADDR`) |
| `services` | the other console services: NSO, the voice lobby, error and play reports, the connection test, play history, the vermillion gateway, the save cloud, PlayFab and Spelunky 2 |
| `acbaa` | Animal Crossing's web API (`acbaa.json`) |
| `store` | `baas.json` |
| `httpx`, `token`, `msgpack` | shared HTTP helpers, JWTs and ids, msgpack |

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

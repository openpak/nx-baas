# Ports — nx-baas (trimmed)

> Trimmed copy for this repository; the canonical document lives at
> `Openpak/ports.md` and governs. Last synchronised 2026-09-15.

One block per concern, nothing below 20000, nothing at or above 27000 (Photon-Reference and
Steam live there). Every service reads its listeners from `<SVC>_HTTP_ADDR`, `<SVC>_GRPC_ADDR`,
`<SVC>_METRICS_ADDR`; the values below are the defaults and the local-run convention. Each
service owns a block of ten: +0 HTTP, +1 gRPC, +2 metrics/pprof, +3..+9 spare.

## 20070 block

| Block | Service | HTTP | gRPC | metrics |
| --- | --- | --- | --- | --- |
| 20070 | Switch adapter (from nx-baas): emulator HTTP API + internal | 20070 | 20071 | 20072 |

## 21000 — console-facing TLS (via Traefik SNI)

| Port | Service | Hostnames (SNI) |
| --- | --- | --- |
| 21000 | Switch adapter: BAAS, Nintendo Account, dauth/aauth/dcert, Penne, Beach, Vermillion, NSO membership, avatar CDN, scsi (saves package), bcat (news package) | all `*.nintendo.*` names the console is redirected to |

## Health

| Service | Endpoint |
| --- | --- |
| Switch adapter (nx-baas) | `/healthz` — answered before host routing, so any console-facing name works |

Other services' rows live in the canonical ports.md.

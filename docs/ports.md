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
| 21000 | Switch adapter: BAAS, Nintendo Account, dauth/aauth/dcert, Penne, Beach, Vermillion, NSO membership and the Lhub page (`*.nso.nintendo.net`), the eShop storefront (`hac.*.savanna.srv.nintendo.net`, `bugyo.`), NIM's pushmo/tagaya/veer/superfly/sun/aqua hosts, avatar CDN, scsi (saves package), bcat (news package; `openpak_*` lists and title topics forwarded to `news` when `NEWS_INTERNAL_URL` is set) | all `*.nintendo.*` names the console is redirected to |

## Health

| Service | Endpoint |
| --- | --- |
| Switch adapter (nx-baas) | `/healthz` — answered before host routing, so any console-facing name works |

## Outbound from the adapter

| Target | Env | Notes |
| --- | --- | --- |
| `news` (block 20040) | `NEWS_INTERNAL_URL`, optional `NEWS_INTERNAL_CA`, `NEWS_INTERNAL_SERVER_NAME` | News lists and title topics, forwarded verbatim. The signed-container server currently runs as `openpak-news-experiment:20040` with TLS under its own CA and a certificate for `bcat-topics-lp1.cdn.nintendo.net`; plain `http://` works when it runs without TLS |

The news push is an internal route on 20070: `POST /internal/news/push` (`X-Internal-Key`).

Other services' rows live in the canonical ports.md.

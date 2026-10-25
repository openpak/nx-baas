# Switch BAAS Server

OpenPak's Switch BAAS Server.

| | |
| --- | --- |
| Network | Nintendo Switch |
| Role | BAAS and Nintendo Account servers for a real CFW Switch: identity, friends, presence and invitations |
| Depends on | [`nx-shop`](https://github.com/openpak/nx-shop), [`nx-penne`](https://github.com/openpak/nx-penne), [`nx-pctl`](https://github.com/openpak/nx-pctl) (required), [`nx-bcat`](https://github.com/openpak/nx-bcat) (optional), [`account`](https://github.com/openpak/account) |
| Image | `ghcr.io/openpak/nx-baas` |
| Licence | AGPL-3.0-only |

## What it serves

| Endpoint | What |
| --- | --- |
| `*.baas.nintendo.com`, `accounts.nintendo.com` | Identity, friends and presence for a console, and the Nintendo Account link flow |
| `*.nso.nintendo.net` | The HOME Menu's Switch Online page |
| `receive.hac.<env>.er.srv.nintendo.net` | Console error reports, forwarded to the website |
| Game API, `:20070` by default (`NX_API_ADDR`) | Internal HTTP for Photon, the emulator and rig tooling; consoles never reach it |

## Run

```sh
go build -o nx-baas .
NX_SHOP_URL=... NX_PENNE_URL=... NX_PCTL_URL=... ./nx-baas
```

The process exits at startup, naming the variable, if one of the three required URLs is unset.
Every other variable is in [deploy.md](docs/deploy.md).

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)
- [Animal Crossing departure contract](docs/acbaa-flight-20261013.md)
- [Archived Ryujinx visit-flow review (2026-10-13)](docs/acnh-archived-client-review.md)
- [The account config carries the online licence](docs/accounts-config-online-license.md)
- [The vphyms account read is a payload envelope, not a 404](docs/accounts-vphyms-payload.md)
- [Proving a real console's BAAS id token](docs/console-id-token.md)
- [Firmware 22.5.0 follow-up: notifications and the eShop, 2026-09-12](docs/firmware-22.5.0-followup-2026-09-12.md)
- [Workstream A review package: friends, profiles and presence](docs/friends-presence-handoff.md)
- [Native online-play invitations (`app.lp1.five.nintendo.net`)](docs/invitations.md)
- [Native OpenPak store: implementation notes and review handoff (workstream D)](docs/native-shop.md)
- [Open questions](docs/open-questions.md)
- [The Penne frontline connection is held open](docs/penne-frontline.md)
- [Why a kind-1 message is acked and then dropped (2026-09-20)](docs/penne-message-delivery-2026-09-20.md)
- [Penne frontline protocol specification (minimum supported), v1](docs/penne-protocol.md)
- [Penne record delivery: what the console actually accepts (2026-09-16)](docs/penne-record-shape-2026-09-16.md)
- [Workstream B review handoff: Penne transport and native notifications](docs/penne-workstream-b-handoff.md)
- [Splitting nx-baas into services](docs/service-split.md)
- [Switch adapter social & presence contracts, v1](docs/social-presence-contracts-v1.md)
- [Store admin internal API (contract v1)](docs/store-admin-api.md)
- [T17BE: Team17's backend, and what Moving Out 2 actually asks for](docs/t17-backend.md)
- [The vermillion device id](docs/vermillion-device-id.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).

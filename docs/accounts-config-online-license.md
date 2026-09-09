# The account config carries the online licence

`GET /v1/accounts/config` on `gw.hac.lp1.vermillion.srv.nintendo.net` fell through to the `gw.`
catch-all and answered a bare `200 {}`. That carries no online licence, so the title reaches the
lobby and stops. This is the third defect in the pre-gRPC REST bootstrap (after device id and
`vphyms`) and it is the actual online gate.

## The fact

The reply must be:

```json
{"payload": "<base64 of a JSON object>"}
```

whose inner object carries:

```json
{"online_license": {"is_available": true}}
```

`is_available: false` — or an absent licence, which is what `{}` amounts to — parks the game at the
lobby with `2321-4992`. This is not a crash or a loop; the bootstrap completes and the game simply
declares itself offline.

Source: `servers/splatoon-3/docs/provenance.md`, "The pre-gRPC REST chain":
`GET /v1/accounts/config` → `{"payload": "<base64 of a JSON object>"}` whose inner object carries
`online_license.is_available: true` — "**This is the online gate.**" A clean-room reading of the
earlier network `splatoon-3` server under `docs/clean-room-policy.md`; no code, structure or
wording carried across.

`online_license.is_available` is the only field we have a measured meaning for, so the inner object
carries only that. The real config has more fields; they are unknown here and omitted rather than
invented. If a capture later names one that matters, it is one line in `payloadEnvelope`'s caller.

## Effect on the console link

Believed none. `config` is a `gw.` vermillion path; no capture we hold of the linking console
touches vermillion. Before this it answered `{}` via the catch-all; it now answers a payload
envelope — same status, a fuller body, the direction the no-`{}` rule prefers. Still console-facing:
confirm the link on hardware first.

## What is not fixed here

The `fro-` frontline route still 404s — its own commit and doc.

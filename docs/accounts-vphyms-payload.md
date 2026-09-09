# The vphyms account read is a payload envelope, not a 404

`GET /v1/accounts/vphyms` on `gw.hac.lp1.vermillion.srv.nintendo.net` answered `404` here. That
is the second defect in the pre-gRPC REST bootstrap an NPLN title runs before it opens a single
gRPC connection, and once device init is past (see `vermillion-device-id.md`) it is the next wall.

## The fact

A `gw.` account read must answer:

```json
{"payload": "<base64 of a JSON object>"}
```

The inner object may be empty. A `404` — or a bare `{}` — reads to the client as *account setup
failed*, and the title restarts its whole bootstrap with a fresh penne id. That loop never ends;
the loading screen never reaches the tenant.

Source: `servers/splatoon-3/docs/provenance.md`, "The pre-gRPC REST chain":
`GET /v1/accounts/<other>` (e.g. `vphyms`) → 200 with the `{"payload": …}` envelope, even if the
inner object is empty. No capture of this exact path exists; the 200 is what breaks the loop. That
table is a clean-room reading of the earlier network `splatoon-3` server for facts under
`docs/clean-room-policy.md` — no code, structure or wording carried across.

This is the same rule the console link already had: **no console reply may be `{}`**. The envelope
around an empty inner object is not a `{}` reply — `{"payload":"e30="}` — so it satisfies it.

## Effect on the console link

Believed none. `vphyms` is a `gw.` vermillion account path; no capture we hold of the linking
console mentions vermillion at all, so there is no evidence the link touches it. If it does, it was
receiving a `404` and now receives a well-formed 200 — the direction the `{}` rule says is right.
Still console-facing: the hardware test confirms the link before anything else.

## What is not fixed here

`GET /v1/accounts/config` still needs `online_license.is_available: true` in its own payload (the
online gate), and the `fro-` frontline route still 404s. Their own commits and docs.

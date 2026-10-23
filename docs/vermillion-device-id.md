# The vermillion device id

`GET /v1/devices/vermillion-device-id` on `gw.hac.lp1.vermillion.srv.nintendo.net` answered
`200 {}` here, because every `gw.` GET did. That is the first defect in the pre-gRPC REST
bootstrap an NPLN title runs before it opens a single gRPC connection, and it is the earliest
one: nothing downstream of it is reachable while it holds.

## The fact

The reply must be:

```json
{"vermillionDeviceId": "<base64 of 16 bytes>"}
```

Three separate things have to be right, each with its own measured failure:

- **The key is camelCase.** A different spelling reads as absent, the client has no device id,
  and it restarts device initialisation forever — the loading screen never reaches the tenant.
- **Sixteen bytes.** The client stores the decoded value as its device identity.
- **No `/` in the encoding.** The client uses the string as a URL path segment; a `/` splits the
  path and crashes it. Standard base64 produces one about 29% of the time, so this is not a
  theoretical case — it has to be excluded deliberately.

Source: `servers/splatoon-3/docs/provenance.md`, "The pre-gRPC REST chain", which records both
failures as measured on hardware. That table records observed facts — endpoint, key spelling, value shape — under `docs/clean-room-policy.md`. No code, structure or wording was carried across.

This is also the local case of the rule this repository already had from the console link: **no
console reply may be `{}`**. An empty object is the known failure class here, not a harmless
default. `{}` was the bug.

## How the value is derived

From the console's own device id, which the SDK puts in its User-Agent —
`NintendoSDK Firmware/<ver> (platform:NX; did:<hex>; eid:lp1)` — hashed, truncated to 16 bytes,
and re-derived with a counter until the base64 has no `/`.

Deriving rather than storing is deliberate: the value has to be **stable** for a console (a
fresh id per request would make it re-register forever) and nothing else about it matters, so a
hash of something already stable is the whole requirement and there is no state to persist,
migrate or lose. The ceiling is written next to the code: a console whose User-Agent carries no
`did:` falls back to a shared value.

## Effect on the console link

Believed none, and this was checked rather than assumed:

- The change adds **one** case, matched on the exact path `/v1/devices/vermillion-device-id`,
  placed after the existing `PUT`/`POST` `/v1/devices/` → 204 case. Every other `gw.` request,
  and every non-`gw.` host, answers exactly as before.
- No capture we hold mentions vermillion at all, so there is no evidence the linking console
  ever requests this path. If it does, it was receiving `{}` and is now receiving a well-formed
  id — the direction the `{}` rule says is right.

Still: this is console-facing, and the link is worth more than any one title. The hardware test
confirms the link **before** anything else.

## What is not fixed here

The other three defects in the same bootstrap, deliberately left for their own rounds and their
own hardware runs — one behaviour change at a time, because logs have misled this diagnosis
before:

1. `GET /v1/accounts/config` must answer `{"payload": base64(json)}` carrying
   `online_license.is_available: true`. This is the online gate; without it a title reaches the
   lobby and stops with `2321-4992`.
2. `GET /v1/accounts/vphyms` answers 404, which makes a title treat account setup as failed and
   restart its whole bootstrap with a new penne id, forever. It needs a 200 with the same
   `{"payload": …}` envelope, even if the inner object is empty.
3. There is no `fro-` route, so the frontline `POST` 404s. It must be held open as a stream for
   room-code registration.

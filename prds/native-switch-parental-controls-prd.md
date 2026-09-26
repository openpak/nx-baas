# Native Switch parental controls

Status: phase 0 implemented plus phase 1's store, awaiting hardware evidence.
Date: 2026-09-26.

Normative evidence:
[docs/parental-controls-firmware-2026-09-26.md](../docs/parental-controls-firmware-2026-09-26.md)
— the pctl firmware study. This PRD does not restate the endpoints, the JSON
vocabulary or the error identities; that document is the contract.

## Objective

Make the console's Parental Controls leave "not set up" against OpenPak, and let
the owner set restrictions from an OpenPak surface instead of Nintendo's
smartphone app. The on-console half (PIN, restriction level, play timer, bedtime
alarm) is local to pctl's system savedata and needs nothing from us; the work is
the pairing handshake and the settings sync on
`api-<env>.pctl.srv.nintendo.net/moon/v1/…`.

## Scope

Owned: a `moon.go` handler in nx-baas, its device/pairing/setting store, the
parent-facing screens in the Flutter app, and the pctl wiring in the three
emulators. Not owned: anything that changes the console (DNS, the ceiling and the
CA already carry this host — `hosts.c` lists `*.pctl.srv`), and Nintendo's
app-facing API, which we never have to imitate because the only fixed contract is
the console-facing one.

Out of scope for this release: age-rating enforcement inside the OpenPak store,
Nintendo's monthly summary mail, and anything that patches a game.

## Phases and gates

Each phase is gated on evidence, not on code review. No phase starts before the
one above it has its gate.

**Phase 0 — one logging endpoint.** Split `api-*.pctl.srv.nintendo.net` off the
`serviceStatus` case in `main.go` into `moon.go`: log method, path, query and
body; answer every `/moon/v1` path with `404 resource_is_not_found` in the moon
error shape. Paths outside `/moon/v1` keep today's service-status answer so
nothing regresses.
*Gate:* one on-console pairing attempt (Settings → Parental Controls → use
smartphone app, any code) produces a log that answers P1–P4 of the study §7 —
verb per endpoint, device-id shape on the wire, pairing-code alphabet, and
whether `activate` precedes `AuthorizePairing`. **Until this log exists, no
request body in phases 1–3 may be invented.**

**Phase 1 — pairing works end to end.** *The shape-independent half is done
ahead of the log (`moon.go`, `Store.PctlDevices`):* the record, a pairing code
with a 15-minute TTL that a console burns on activation, owners as `User.NaID`,
the setting document held as received with an ETag computed over it, and
`POST /internal/pctl/pairing` to mint a code. What is left is the console-facing
envelope — code lookup, `activate`, `owners`, `GET parental_control_setting` —
which the phase-0 log supplies, plus the screen in `app/lib/` that calls the
internal route and shows the console once it pairs.
*Gate:* on hardware the Parental Controls screen shows the console as managed and
names the paired account; no reboot needed.

**Phase 2 — the setting restricts.** `PUT parental_control_setting` and
`whitelisted_applications`, ETag on the setting document, `304` for
`If-None-Match`. Parent UI gains the restriction-level editor.
*Gate:* a rating limit set from the app makes a title above that rating refuse to
launch on the console after a sync, and a whitelisted title still launches.

**Phase 3 — time features and push.** Play timer and bedtime-alarm fields,
`POST events` (stored, not interpreted), `players/` and icons, the extra-time
grant with `409 over_the_time_limit` as its refusal. Then the npns digital-twin
notification over the existing Penne delivery path.
*Gate:* a bedtime alarm fires on the console at the configured time, and a
setting changed from the app lands without waiting for the `bgtc` poll.

**Phase 4 — emulators, Ryujinx first.** Fetch and cache the setting document in
`OpenPakSession` (it already holds the dauth device token), then feed
`IsRestrictionEnabled`, `CheckFreeCommunicationPermission`,
`IsFreeCommunicationAvailable` and the stereo-vision commands from it instead of
from constants. One OpenPak PIN dialog for temporary unlock, identical in all
three emulators. Port to Citron and Eden in the same release.
*Gate:* a restricted account cannot start a free-communication feature on any of
the three, and the unlock dialog lifts it for the session only.

## Server-side enforcement

Decide before phase 2 ships, because it is cheap alongside the setting store and
awkward to retrofit: client-local enforcement is all the console offers, so a
modded console or an emulator can ignore the setting. If a restricted account is
to be genuinely unable to chat, use voice, send invitations or post UGC, the
check belongs in the handlers that serve those, keyed on the same setting
document. Phase 2 stores it; the check is one predicate per feature.

## Non-goals and known limits

No game patches (the standing rule). No new service or repository: the handler
lives in nx-baas beside the other console surfaces, and the parent UI in the
existing app. The explainer video
`parentalcontrols-movie-<env>.cdn.nintendo.net/default/switchpc_en.mp4` is routed
and serves whatever `PCTL_MOVIE` points at, logging a 404 while that is unset —
no clip is invented, because whether the setup screen blocks on it is still P5. Verbs and bodies for phases 1–3 stay unwritten until the phase-0 log
supplies them.

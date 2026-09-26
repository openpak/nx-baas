# Native Switch parental controls

Status: phases 0 and 1 implemented end to end; the console-facing shapes are
inferred from the firmware and await one on-console pairing to confirm.
Date: 2026-09-26.

Normative evidence:
[docs/switch/parental-controls-firmware-2026-09-26.md](../../docs/switch/parental-controls-firmware-2026-09-26.md)
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

**Phase 1 — pairing works end to end.** *Implemented, unconfirmed.* The store
(`moon.go`, `Store.PctlDevices`): a record, a pairing code with a 15-minute TTL
that activation burns, owners, and the setting document held as received with an
ETag over it. The parent surface: `app/lib/parental_controls_page.dart` on the
Account tab (app v0.15.0) through
`GET`/`POST /api/v1/me/parental-controls[/pairing]` on the website (v0.61.0),
which relays to the internal API with `X-Internal-Key`
(`website/internal/pctl`). The console-facing endpoints: the code search,
`activate`, device read/update/unlink, owners, the setting document with `304`,
`whitelisted_applications`, events and `players`; `copy` still refuses, because
there is no second console to copy from.

Their shapes come from the firmware's field names, not from a log, so they are
**unproven** and the phase-0 dump stays on beside every answer. Two unknowns are
made self-correcting rather than fatal: a device id resolves whether the console
spells it hex or decimal (§7 P2), and an unknown code answers an empty
`{items,count}` list rather than a 404, because "none" answers the question asked.
*Gate:* on hardware the Parental Controls screen shows the console as managed and
names the paired account; no reboot needed. Everything above is the guess that
gate tests.

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

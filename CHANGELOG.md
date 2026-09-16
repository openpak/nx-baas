# Changelog — nx-baas

Generated from git history on 2026-09-15. `git log` stays the source
of truth; this file is the readable summary.

## v0.12.40 — 2026-09-16

- Deliveries addressed to the BAAS account, not the certificate the console presents: the Penne bearer on `god.*` routes is the device token (subject = certificate), so `NoteAccount` keyed console account ids by a cert that `AccountsFor` could never match and every frame left unaddressed — the friends module drops a zero uid by design; `ResolveUser` at the record sites, `BindConsole` heals cert-keyed entries including on an already-bound login. Found live on prod: a natural presence write reached a connected console with no reconnect (the shape failure is gone) but unaddressed [6d8fe42]

## v0.12.39 — 2026-09-16

- docs: say plainly that prod is two commits behind the carrier fix [680f033]
- N5 answered from the friends module's own init: it registers its own program id (`0x010000000000000e`) as an npns listen key (u64 Listen, proxy slot 5) and starts its `nn.friends.EventWatcher` thread only if Listen succeeds [4009ab2]
- Penne notification carried as the kind-1 message it is: envelope slot 2 string `"NX"`, `PutRecord{[Entry], u8 1}` → `Entry{kind 1 → Message{name, u16, Meta{receivers, 32-hex account id}, body, deliverAt}}`; `BuildMessage`/`ParseMessage`, one frame per account from `AccountsFor`; the six-way `NX_PENNE_RECORD_PROBE` rotation, the refuted PutRecord shape and the record-name constants deleted [522fbe2]
- docs: recover the PutRecord message shape from 22.5.0; close N2, open N5 [4908cdb]
- docs: correct the friend-list branch's fate on origin [4b26bcc]
- docs: record the worktree prune and the retired friend-list branch [56319da]
- docs: move PRDs in-house; scaffold next-session, changelog and shared docs [1e873f3]

## v0.12.38 — 2026-09-12

- Answer the console's LeafHash (0x07): decode the leaf listing and reply in the console's shape behind `NX_PENNE_RECONCILE`; unanswered, the console abandons the sync after the measured ~70 s [481388d]

## v0.12.37 — 2026-09-12



## v0.12.36 — 2026-09-12



## v0.12.35 — 2026-09-12



## v0.12.34 — 2026-09-12



## v0.12.33 — 2026-09-12



## v0.12.32 — 2026-09-12



## v0.12.31 — 2026-09-12



## v0.12.30 — 2026-09-12



## v0.12.29 — 2026-09-12



## v0.12.28 — 2026-09-12



## v0.12.27 — 2026-09-12



## v0.12.26 — 2026-09-12



## v0.12.25 — 2026-09-12



## v0.12.24 — 2026-09-12



## v0.12.23 — 2026-09-12



## v0.12.22 — 2026-09-12



## v0.12.21 — 2026-09-12



## v0.12.20 — 2026-09-12



## v0.12.19 — 2026-09-12



## v0.12.18 — 2026-09-12



## v0.12.17 — 2026-09-12



## v0.12.16 — 2026-09-12



## v0.12.15 — 2026-09-12



## v0.12.14 — 2026-09-12



## v0.12.13 — 2026-09-12



## v0.12.12 — 2026-09-12



## v0.12.11 — 2026-09-12



## v0.12.10 — 2026-09-12



## v0.12.9 — 2026-09-12



## v0.12.8 — 2026-09-12



## v0.12.7 — 2026-09-12



## v0.12.6 — 2026-09-12



## v0.12.5 — 2026-09-12



## v0.12.4 — 2026-09-12



## v0.12.3 — 2026-09-12



## v0.12.2 — 2026-09-11



## v0.12.1 — 2026-09-11



## v0.12.0 — 2026-09-11



## v0.11.0 — 2026-09-10



## v0.10.0 — 2026-09-10



## v0.9.0 — 2026-09-10



## v0.7.30 — 2026-09-09



## v0.8.0 — 2026-09-09



## v0.7.29 — 2026-09-09



## v0.7.28 — 2026-09-08



## v0.7.27 — 2026-09-08



## v0.7.26 — 2026-09-08



## v0.7.25 — 2026-09-08



## v0.7.24 — 2026-09-08



## v0.7.23 — 2026-09-08



## v0.7.22 — 2026-09-08



## v0.7.21 — 2026-09-08



## v0.7.20 — 2026-09-08



## v0.7.19 — 2026-09-08



## v0.7.18 — 2026-09-08



## v0.7.17 — 2026-09-08



## v0.7.16 — 2026-09-08



## v0.7.15 — 2026-09-08



## v0.7.14 — 2026-09-08



## v0.7.13 — 2026-09-08



## v0.7.12 — 2026-09-08



## v0.7.11 — 2026-09-08



## v0.7.10 — 2026-09-08



## v0.7.9 — 2026-09-08



## v0.7.8 — 2026-09-08



## v0.7.7 — 2026-09-08



## v0.7.6 — 2026-09-08



## v0.7.5 — 2026-09-08



## v0.7.4 — 2026-09-08



## v0.7.3 — 2026-09-08



## v0.7.2 — 2026-09-08



## v0.7.1 — 2026-09-08



## v0.7.0 — 2026-09-08



## v0.6.2 — 2026-09-08



## v0.6.1 — 2026-09-08



## v0.6.0 — 2026-09-08



## v0.5.5 — 2026-09-08



## v0.5.4 — 2026-09-08



## v0.5.3 — 2026-09-08



## v0.5.2 — 2026-09-08



## v0.5.1 — 2026-09-08



## v0.5.0 — 2026-09-07



## v0.4.0 — 2026-09-07



## v0.3.0 — 2026-09-07



## v0.2.9 — 2026-09-07



## v0.2.8 — 2026-09-07



## v0.2.7 — 2026-09-07



## v0.2.6 — 2026-09-07



## v0.2.5 — 2026-09-07



## v0.2.4 — 2026-09-07



## v0.2.3 — 2026-09-07



## v0.2.2 — 2026-09-07



## v0.2.1 — 2026-09-07



## v0.2.0 — 2026-09-07



## v0.1.2 — 2026-09-07



## v0.1.1 — 2026-09-07



## v0.1.0 — 2026-09-07



## frozen-20260907 — 2026-09-07



## frozen-20260907 — 2026-09-07

- License: AGPL-3.0 [9cb6f7c]
- debug: log every TLS ClientHello by SNI (spot non-HTTP frontline connections) [c87fe51]
- NSO memberships (capi.lp1.op2) and NA qrcode_param, VPS parity; capi in the fixed cert [0808537]
- VPS parity: full push_channels object, application block in id_token, default thumbnails for unlinked users [bf9168c]
- userObj: etag mirrors bs:did for linked users (VPS parity) [a39a7ea]
- TLS: random cert serials (same-second mints shared a serial) [e391076]
- TLS: fixed multi-SAN cert for every name it covers; on-demand certs only for unrouted SNI (console 2123-0013) [1e7066f]
- Serve nxAccount only from the user's own uploaded blob; drop the global probe constant [329a754]
- Login: a pre-seeded device with an empty password adopts the one it presents (console mirror) [8ed31bc]
- Serve the fixed multi-SAN cert in capture mode; per-SNI certs elsewhere; verbatim nxAccount probe blob [cdbf276]
- Penne/Beach/Vermillion registration answered; profile blob gets a fresh uid [5b67e64]
- Probe: NX_TEST_NXACCOUNT serves a console profile blob in extras.self for linked users [5aa3472]
- Match the captured VPS login: token headers/claims, user object, device snapshot, silent authorize for system applets [51c4546]
- Federation = Restore User: return the account's canonical BAAS user with this console's device account [f9746c8]
- Bisect switch NX_MINIMAL for the federation user object; access token claims per documentation [ec24fc4]
- playLog passed through as the string it already is; NX_DEBUG logs BAAS/NA request and response bodies [66957fc]
- Federation keeps the console's BAAS user id; stale users for the same PID are unlinked [6dd6c54]
- BAAS user object: avatars as https URLs on the cdn-image host, bare friend-code ids [7bc6e9c]
- access token issuer on m-lp1 as well [600b48d]
- BAAS token issuer on m-lp1 too: the console derives its key-set URL from the token and had the VPS keys cached for the old host [3316b19]
- Distinct kid for Nintendo-Account tokens: the console binds kid to issuer and rejects a kid shared with BAAS [bc46aff]
- BAAS token jku on m-lp1: the console caches key sets per URL and had the VPS's for the old URL [31d7964]
- NA tokens and users/me shaped exactly like the captured VPS responses [f9ce2c5]
- capture: mask form passwords in the log [43e8a4a]
- Capture mode (NX_UPSTREAM): pass-through to a real deployment with full request/response logging [e7b71d2]
- users/me: the exact minimal object a console accepts; no scope in the token response [9cadb77]
- users/me: minimal, null-free profile; id lowercase; nickname bounded [2b85c27]
- Adopt unknown device accounts on first use (consoles previously linked to the VPS) [1c94499]
- NA token: scope as string, signed refresh tokens (survive restarts); users/me: timestamp types [4bea7df]
- Server cert validity 2020-2036: a console clock behind ours must not see a not-yet-valid cert [690612a]
- nx-baas: BAAS + Nintendo Account servers for a real CFW Switch, backed by openpak-account [223c063]


# Open questions

One row per thing we do not know, with the evidence so far and the **next
experiment** — not a wish list. Close a row by deleting it and writing what was
found into the spec it belongs to. Dates are when the row was last touched.

Status: **blocked** (needs something we cannot do yet) · **armed** (an
experiment is deployed and waiting) · **open** (nobody has started) ·
**answered** (settled; the row stays only until its finding has a home in a
spec, then it is deleted — N1's home is `docs/penne-protocol.md` §4f).

## Notifications

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| N1 | What sync answer does the console accept? | **ANSWERED** 2026-09-12 | An **empty entry vector**. Four wake cycles on hardware, six candidates each: mirroring the console's own digests, a two-slot envelope, count+1, a LeafHash mirror and silence all leave it reconnecting; only `RootHash` with no entries produces `SyncComplete`, every time. Live in production from v0.12.29 | — |
| N2 | Is `PutRecord{c-friends.inv.subsTypes, <event json>}` accepted, and does it wake the friends module? | **ANSWERED** 2026-09-16: **no** — that name is a record the friends module writes and the console uploads; a notification is a kind-1 *message* inside PutRecord, and our frame nesting was wrong on three counts (`docs/penne-record-shape-2026-09-16.md`). Remaining half: the receiver token (N5) | record shape from `0x1dc430`; topic from `0x17bd24`. The sync gate above it is closed (N1; `docs/penne-protocol.md` §4f). Caveat from §4f: the observed connection subscribed only `nx_data_<titleId>` topics — `c-friends.inv.subsTypes` belongs to the friends module's own init, so first confirm the subscription shows up (opening the friend list is the natural trigger) before judging delivery | with both consoles registered (the unknown-id mint keeps the second one unlocked), send a friend request from one to the other: `podman logs … \| grep -e subscribed -e ack=` and does the receiving list refresh without a reboot |
| N5 | Which `Meta.f1` receiver token reaches the friends module? | open 2026-09-16 | friends issues no Listen command; keys are matched by u64 or name (`FUN_001a09a0`) | one delivery with `0x010000000000000e`, watch for the unsolicited friend-list GET |
| N3 | What is `presence.pf`? A one-byte enum stored at friend+`0x569` | **blocked** 2026-09-12 | probed: the module has string tables for presence states, channels and request states, and **none for a platform**. `pf` is written and never compared anywhere in the module | only a real capture can settle it. Do not hunt again — the negative result is the finding |
| N4 | Which `channels[*]` value belongs on an invitation? | open 2026-09-12 | **the value set is recovered**: a string→int mapper at `0x1a7d80` over a `.rodata` table — `NX_FACED, FRIEND_CODE, IN_APP, NINTENDO_ACCOUNT, 3DS, NNID, FACEBOOK, TWITTER, WECHAT, CAMPUS`. Our friend requests already send `FRIEND_CODE`, which is in the set | which one an *invitation* carries is the open half. `IN_APP` is the candidate for a game-issued invite; a hardware capture of one real invitation settles it |

## Friends and presence

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| F1 | How does the play-history document travel? | open 2026-09-12 | **the console builds it**, not just reads it: the module carries the format fragments `"firstPlayedAt":%lld,` `"lastPlayedAt":%lld` `"totalPlayCount":%u,` `"totalPlayTime":%u,` — so timestamps are signed 64-bit and the counters unsigned 32-bit. Still **no URL anywhere**, which leaves a record as the only carrier | log the topics and values the console writes now that connections reach the steady state (`docs/penne-protocol.md` §4f); that also tells us whether it publishes to `c-friends.*` or `c-storage.summary` |
| F2 | Does the friend list refresh from anything except a notification? | open | `cooldown_time_for_sync_friend_list` defaults to 30 s, so it is not throttling | after N2, leave two consoles idle and see whether a list ever self-corrects |

## eShop

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| S1 | What are `pearljam…/civil` and `/sugar`? | open | the only eShop hosts in NIM with no recovered contract | the handler dumps the full request; open the shop applet on hardware and read the log |
| S2 | What does `/v1/a/<appId>/dv` return? | open 2026-09-12 | probed and **ruled out**: NIM has no `version`/`required_version`/`format_version` JSON paths at all, and `0x20e690` parses headers (`"%s: %s"`), not a body. The `$.ttl`/`$.weights` and `$.individual`/`$.is_available` parsers belong to other calls | stop looking for JSON field names; capture one real response, or trace what the request function does with the body it receives |
| S3 | What does an ES-trusted eticket require? | blocked | NIM parses `cert_chain`, `common_key_generation`, `signing_key`, `payload`, `payload_key_iv`, `wrapped_payload_key`; we cannot mint one | unchanged: this is the native-install gate, and no server change moves it |
| S4 | Which of the stubbed NIM routes does a real store journey actually touch? | open | §14 lists what each answers and why | watch the log during an acquisition on hardware; anything that appears is worth implementing properly |

## News

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| W1 | What does `/api/nx/v1/titles/<titleId>/topics` return? | **answered** 2026-09-12 | the `bcat` sysmodule is dumped; `FUN_00215590` reads `$.topic_id`, `$.na_required`, `$.test_distribution`, `$.service_status`, `$.directories[0].data_list[]` out of a **msgpack** document (§21d). Implemented in `bcat.go` | — |
| W2 | What is a BCAT delivery-cache container, and what does it verify? | **partly answered** 2026-09-12 | the list document names every file by `url` + `size` + `digest`, and the module fetches each with a plain conditional GET (§21c). What the on-disk delivery cache does with them (the `bafmeta` sidecar, the per-title `passphrase.bin`) is still unread | read `nn.bcat.Downloader` / `nn.bcat.NaCacheUpdater` in `~/openpak-firmware-audit-22.5.0/bcat`; only needed the day OpenPak publishes a container |
| W3 | What does `POST fw-api.<env>.nso.nintendo.net/v1/events` send and return? | open 2026-09-12 | URL, method, `Authorization: Bearer <token>` and `Content-Type: application/json` are confirmed (`FUN_001c5190`, `FUN_001c3050`); the body is built by a serializer with no string literals and the reply is read by a streaming SAX handler, so no field names fall out of the module | capture it on hardware — it is a JSON POST, so the log line is the answer. Unimplemented until then: a guessed shape would read as a working feature |
| W4 | Which Penne carrier delivers a `news` / `news_pickup` push? | open 2026-09-12 | `bcat` reads pushes from `npns:s` and switches on `$.type` (§21e); it subscribes to no `c-*` topic, unlike friends | the frontline reaches the steady state since the sync answer (`docs/penne-protocol.md` §4f) — write a `news_pickup` push to an `nx_data_<titleId>` topic the console already subscribes to, and watch for a `/api/nx/v1/list/` request |
| W5 | Is `{"ip": …}` the key `nn::netdiag` reads? | open 2026-09-12 | prepo and the connection test are implemented (`netdiag.go`); the `/v1/ip` key name comes from public research, not from the module — `ExtractIpAddress` parses with a SAX handler whose member comparison did not fall out of the binary | run the connection test on hardware: it either shows a global IP or does not |

## Unserved hosts (§22c)

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| U1 | Which of the thirteen unrouted hosts does a console actually contact? | open 2026-09-12 | §22c lists each with its module; all resolve here already and land in the log as `!! UNHANDLED host` | read the log after a session that opens the album, the NSO app surfaces and parental controls |
| U3 | The console's own IP is not visible to any handler. | open 2026-09-12 | Traefik routes the console entrypoint with `tls: passthrough`, so it splices the TCP connection and adds no headers; the only address downstream sees is the previous hop's (verified live: `/v1/ip` answered `10.89.2.12`). `/v1/ip` now reports what it can see and logs that the address is not public, rather than presenting 10.x as a global IP | PROXY protocol on the Traefik TCP router, parsed in the listener, is the only thing that carries the real source through a passthrough |
| U2 | Is `$.user.op2.membership.active` read off a response we send? | **answered** 2026-09-12 | No. It sits in one selector table with `$.user.id` and `$.events[0]` (`FUN_00217500`), i.e. a `{user:{…}, events:[…]}` document — the Nintendo Account **event poll**, not the login reply and not the `/2.0.0/users/me` we serve (which returns the user unwrapped and which hardware accepts). `op2.membership_right_committed` / `op2.membership_right_expired` are the event types that go in that array | nothing to change. If the event poll is ever implemented, membership changes belong in it |

## Method

The tooling that answers these lives in `tools/firmware/` with its own README.
Two habits that paid off: grep a module for `expected, but` before anything
else, because a state machine names its own sequence in its error strings; and
when a shape is ambiguous, make the console the oracle — log what it sends and
vary what you send back — rather than reading further.

# Open questions

One row per thing we do not know, with the evidence so far and the **next
experiment** — not a wish list. Close a row by deleting it and writing what was
found into the spec it belongs to. Dates are when the row was last touched.

Status: **blocked** (needs something we cannot do yet) · **armed** (an
experiment is deployed and waiting) · **open** (nobody has started).

## Notifications

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| N1 | Which sync answer does the console accept? Ours is byte-structurally identical to its own RootHash and is still refused | **armed** 2026-09-12 | `docs/penne-protocol.md` §4e; two candidates eliminated (mirror, two-slot envelope) | `NX_PENNE_SYNC_PROBE=1` is set on prod and the counter is durable: the next console wake tries `count+1`, `LeafHash`, an empty vector, then silence. Read `podman logs … \| grep answered` |
| N2 | Is `PutRecord{c-friends.inv.subsTypes, <event json>}` accepted, and does it wake the friends module? | blocked on N1 | record shape from `0x1dc430`; topic from `0x17bd24` | after N1, accept a friend request on one console and watch the other's list |
| N3 | What is `presence.pf`? A one-byte enum stored at friend+`0x569` | **blocked** 2026-09-12 | probed: the module has string tables for presence states, channels and request states, and **none for a platform**. `pf` is written and never compared anywhere in the module | only a real capture can settle it. Do not hunt again — the negative result is the finding |
| N4 | Which `channels[*]` value belongs on an invitation? | open 2026-09-12 | **the value set is recovered**: a string→int mapper at `0x1a7d80` over a `.rodata` table — `NX_FACED, FRIEND_CODE, IN_APP, NINTENDO_ACCOUNT, 3DS, NNID, FACEBOOK, TWITTER, WECHAT, CAMPUS`. Our friend requests already send `FRIEND_CODE`, which is in the set | which one an *invitation* carries is the open half. `IN_APP` is the candidate for a game-issued invite; a hardware capture of one real invitation settles it |

## Friends and presence

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| F1 | How does the play-history document travel? | open 2026-09-12 | **the console builds it**, not just reads it: the module carries the format fragments `"firstPlayedAt":%lld,` `"lastPlayedAt":%lld` `"totalPlayCount":%u,` `"totalPlayTime":%u,` — so timestamps are signed 64-bit and the counters unsigned 32-bit. Still **no URL anywhere**, which leaves a record as the only carrier | log the topics and values the console writes once N1 is through; that also tells us whether it publishes to `c-friends.*` or `c-storage.summary` |
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
| W1 | What does `/api/nx/v1/titles/<titleId>/topics` return? | open 2026-09-12 | the console asks for it live; our news service implements a different path family and the request falls through to an empty list (§20) | dump the News applet (`0x0100000000001000`) and read its parser |
| W2 | What is a BCAT delivery-cache container, and what does it verify? | **blocked** 2026-09-12 | only the IPC proxy names survive in `ns`; the logic is in the bcat sysmodule, which the audit never dumped although the firmware has it | extract `0x010000000000000c` (hactool + `nx2elf`, neither currently installed) and mine it. Serving topics without this only moves the failure later |

## Method

The tooling that answers these lives in `tools/firmware/` with its own README.
Two habits that paid off: grep a module for `expected, but` before anything
else, because a state machine names its own sequence in its error strings; and
when a shape is ambiguous, make the console the oracle — log what it sends and
vary what you send back — rather than reading further.

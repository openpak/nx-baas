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
| N3 | What is `presence.pf`? A one-byte enum stored at friend+`0x569`, never compared, never published by the console | open | §15 | capture a real Nintendo presence document, or find a reader of that byte in the friends IPC marshalling |
| N4 | What are an invitation's `channels[*]` values? | open | read at `$.items[*].channels[0]`, never written by the module | as N3 — nothing local can settle it |

## Friends and presence

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| F1 | Which endpoint serves the play-history document (`firstPlayedAt`, `lastPlayedAt`, `totalPlayCount`, `totalPlayTime` per title)? | open | parsed only by the friends module; **no URL in its strings** | suspect it arrives as a record (`c-storage.summary` is the shape-alike); confirm by logging record topics once N1 is through |
| F2 | Does the friend list refresh from anything except a notification? | open | `cooldown_time_for_sync_friend_list` defaults to 30 s, so it is not throttling | after N2, leave two consoles idle and see whether a list ever self-corrects |

## eShop

| # | Question | Status | Evidence | Next experiment |
| --- | --- | --- | --- | --- |
| S1 | What are `pearljam…/civil` and `/sugar`? | open | the only eShop hosts in NIM with no recovered contract | the handler dumps the full request; open the shop applet on hardware and read the log |
| S2 | What does `/v1/a/<appId>/dv` return? | open | NIM's update check, built at `0x1ecbe0`; we answer 404 | decompile the response parser at `0x20e690`, or capture one from hardware |
| S3 | What does an ES-trusted eticket require? | blocked | NIM parses `cert_chain`, `common_key_generation`, `signing_key`, `payload`, `payload_key_iv`, `wrapped_payload_key`; we cannot mint one | unchanged: this is the native-install gate, and no server change moves it |
| S4 | Which of the stubbed NIM routes does a real store journey actually touch? | open | §14 lists what each answers and why | watch the log during an acquisition on hardware; anything that appears is worth implementing properly |

## Method

The tooling that answers these lives in `tools/firmware/` with its own README.
Two habits that paid off: grep a module for `expected, but` before anything
else, because a state machine names its own sequence in its error strings; and
when a shape is ambiguous, make the console the oracle — log what it sends and
vary what you send back — rather than reading further.

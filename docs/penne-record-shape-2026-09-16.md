# Penne record delivery: what the console actually accepts (2026-09-16)

Static pass over the 22.5.0 `npns` and `friends` modules plus one runtime
capture (the console's own `PutRecord` at 08:34 UTC today). Addresses are
Ghidra (+0x100000). Nothing below is hardware-confirmed as *delivery*; the
shapes are.

## 1. `c-friends.inv.subsTypes` is written BY the console, not read by it

`FUN_001eaa30("c-friends.inv.subsTypes", "friend", 6)` in friends is a proxy
call on `npns:s` vtable slot 49. The server handler (`FUN_0019da00` →
`FUN_001a3b80` → `FUN_001d0740` → `FUN_001d03f0`) writes the pair into the
console's local record store and marks it for upload. That is the record the
console synced up to us at 08:34 (`c-storage.summary` is the same path).
Writing to that name from the server is a no-op for the friends module.
Open question N2 is answered: **no**.

## 2. `PutRecord` framing, from the console's parser (`FUN_001dfbb0`) and its own frame

```
Envelope   {0: u8 type=4, 1: →PutRecord, 2: string "NX", 3: u64 issued, 4: u64 expires}
PutRecord  {0: [Entry] (exactly one element), 1: u8 = 1}
Entry      {0: u8 kind, 1: →Record}          kind 2 = stored record, kind 1 = message
Record(2)  {0: string name (<32), 1: →Meta, 2: u8 = 1, 3: [ubyte] value}
Message(1) {0: string name (≤47), 1: u16 type, 2: →Meta, 4: string body (≤4095), 5: u64 deliverAt}
Meta(1)    {1: string receivers, 2: string accountId, 4: string (≤39)}
```

- Envelope slot 2 is a **string "NX"**, not a count; our `BuildRootHash`/
  `BuildPutRecord` write a u32 there. The console tolerated it on RootHash
  (empty vector) but a verifier-checked PutRecord is not the same bet.
- Our `BuildPutRecord` puts `{name, value}` directly in envelope slot 1. The
  parser reads slot 0 of that table as a vector length and aborts
  (`FUN_001062a0`) when it is not 1. Production log: every record we wrote
  was followed within a second by a fresh frontline connection.
- Kind 2 stores the value and announces the name (`FUN_001dc430` →
  `FUN_001d0840`). Kind 1 is a **message**: `FUN_001dc510` parses it with
  `FUN_001d69f0`, queues it by `deliverAt` (absent ⇒ now), and hands it to the
  IPC layer (`FUN_001a7a40`) as the 0x10a0-byte struct the friends module
  reads: uid at +0x30/+0x38, body length at +6, body at +0xa0. A notification
  is therefore a **kind-1 message**, not a record.
- `Meta.f2` is the 128-bit account id as **32 hex chars** (optional `0x`),
  parsed by `FUN_001e9000`; an empty string leaves the uid zero and the friends
  handlers drop the event. It is the same id the console puts in
  `/v1/accounts/<32hex>/notification_tokens`, which we record (`NoteAccount`).
- `Meta.f1` is a **comma-separated receiver list**: each token is a hex u64
  (`0x…`, 16 digits, `FUN_001af4f0`) or a name (letters/digits/`-`, ≤31,
  `FUN_001af690`). It must be non-empty. A token `penne` makes npns treat the
  body as its own control message (`onset`, `presence:*`); anything else is
  routed to IPC clients whose listen keys match (`FUN_001a09a0`), else to the
  wildcard listeners, else to an undelivered queue.
- The body is JSON; the friends dispatcher parses it into a 1 KiB scratch
  buffer, so keep events under 1 KiB.
- `DeleteRecord` payload is `{0: [string name]}` (`FUN_001e01f0`).

## 3. Still open: the receiver token the friends module listens under

The friends module never calls any Listen command (slots 5/10/14/25) on its
npns proxy; the only commands it issues are Receive, GetReceiveEvent, GetState,
three event getters, the record write above, and a presence-publish
(cmd 55). How its session acquires a listen key is not visible statically.
Best candidate for `Meta.f1`: the friends program id, `0x010000000000000e`.
Hardware settles it in one delivery: send a kind-1 message with that token,
the recipient's 32-hex account id, and `{"type":"friend_request_authorized"}`,
and watch for the unsolicited `GET /2.0.0/users/<id>/friends`.

## 4. What to change (in order)

1. `internal/penne`: envelope slot 2 → string "NX"; add `BuildMessage(name,
   receivers, accountID, body)` producing the nesting above; keep
   `BuildPutRecord` only for the kind-2 shape (unused by delivery).
2. `penne_deliver.go`: drop the six-way `NX_PENNE_RECORD_PROBE` rotation; one
   shape. Address with `AccountsFor(userID)` (per-account map), not
   `AssocByID(...).AccountIDs[0]` (first account on the console).
3. Keep `presence_updated`/invitation bodies as recovered in the followup doc
   §15; they ride unchanged inside the message body.
4. Then the two-console run: friend request, accept, remove, presence.

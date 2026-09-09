# Proving a real console's BAAS id token

`POST /internal/switch/identity` now accepts an `id_token` field beside the `openpak` and `pid` it
already took. That is the whole change, and it is what stands between a retail console and a NEX
login.

## The fact

A NEX title's login carries a JWT in `AuthenticationInfo.Token`. **A retail console sends a plain
BAAS id token with no binding claim in it; only an emulator build adds a server-specific claim.**
So a title server that can only prove a claim can only serve an emulator: with a real console it
finds no claim and refuses a login that is perfectly genuine. Treating a missing claim as an error
*is* the bug.

Source: `servers/nex/docs/provenance.md`, "Identity", read from the earlier network NEX core for
facts under `docs/clean-room-policy.md` — the token's location, its shape, and which builds add a
claim. No code, structure or wording was carried across. `servers/nex/docs/design.md` names this
as the one cross-repo dependency and puts it in this repository, not that one.

`servers/nex`'s `Host.PlayerByToken` already sends the whole token as `id_token` alongside the
claim, so the wire was ready and nothing on the other side has to change.

## Why nx-baas can prove it, and nothing else can

nx-baas mints that id_token itself, at `/1.0.0/login`, signed with its own RSA key. So the
signature is the proof, and this is the only service holding the key to check it — which is the
reason the title servers deliberately do not. The subject is the BAAS user id, which is the
store's own key, so the lookup from a proven token to an account is a map read.

## What keeps this from becoming a hole

**Every token this service signs uses the same key** — the BAAS access token, the
Nintendo-Account access, id and refresh tokens, all of them. A valid signature therefore says
nothing about what *kind* of token it is. Three checks, and all three are load-bearing:

1. `typ == "id_token"` — an access token says `token`, a refresh token says `refresh`, and the
   Nintendo-Account id token has no `typ` at all. Without this, an access token for the same
   account buys a game login. That case is in the test, and it was confirmed by removing the
   check and watching the test fail with a 200.
2. `iss == baasIssuer` — a Nintendo-Account token is signed by the same key with a different
   issuer, and is not a console login.
3. `exp` in the future. Nothing else in this service checked expiry, because nothing else needed
   to; a login does.

Then the subject must resolve to a user that is actually **linked** (`PID != 0`). An unlinked
BAAS user has a valid token and no account behind it.

`openpak` still takes precedence when both fields are sent, so every emulator login goes down exactly
the path it did before.

## A nuance worth recording

OpenPak's own id_token *does* carry an `openpak` claim when the account is linked, because this
service adds one — unlike Nintendo's, which is where the "no claim" fact comes from. So for a
linked account the claim path may well work too. The `id_token` path is still the one to rely on:
it does not depend on the title server locating and extracting a claim from a framing that varies
by NEX version and title, and it still works when the account core was unreachable at login time
and no claim was minted.

## Effect on the console link

None. This is a new field on an internal, key-guarded endpoint (`X-Internal-Key`, port 20070) that
no console ever calls. The console-facing surface — `/1.0.0/login`, `/1.0.0/federation`, the
Nintendo Account endpoints, the user object — is not touched, and no token's contents changed. The
`openpak` and `pid` branches behave exactly as before; the new branch is only reachable by sending a
field nothing sent until now.

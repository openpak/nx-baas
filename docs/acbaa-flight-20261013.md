# Animal Crossing departure contract

Status: resumed at owner request after the rollback baseline also failed. The
binding fix and shared Animal Crossing integration are deployed and healthy.
Private diagnostics proved the saved player ID resolves to the authenticated
caller, but the optional island cache has no binding. The added binding gate is
removed; full race suite and vet passed, including the migrated-player/no-binding
regression. A live replay of the rejected player/island values returned 200 and
the exact decoded credential structure. Owner confirmed the flight worked after this fix. The temporary
diagnostic capture and capture code were removed after verification.

Recovered from the owner's ACNH main build
`FF1D1C05670DB6021C85B624A710B963`, matching the phone's Harbor log.
SDK build `A226048605D3597F90CB1067D141CD36647B90CD` also matches.
Existing extracted NSOs and the analyzed main303.elf were used read-only;
no firmware, game, emulator configuration, or saves were modified.

Ghidra project has image base 0x100000. Code evidence:

- `006a9800`: POST `/api/v1/emigrations`, MessagePack map of three keys:
  `land_id` (unsigned 64-bit), `my_user_id` (unsigned 64-bit), `user_ids`
  (array of unsigned 64-bit). Clears per-user output and seeds requested IDs.
- Callback at `04bdf5f8` points to `006a9c84`, which delegates to `006a9ca0`.
- `006a9ca0`: response paths `$.land.id`, `$.land.password`, `$.users[]`.
  Sets three required section bits. `006a9800` returns result `0x2adb`
  (module 219, description 21 / 2219-0021) unless all three are parsed.
- `006a9e50`: each user requires `$.users[*].id` and `.password`. Password
  may be nil: that user's output is cleared. Otherwise it is a string.
  Entries must match requested IDs; every requested nonzero ID must be handled.
- `006947d4` accepts an unsigned/nonnegative integer into the 64-bit ID.
  `006948b4` accepts a string shorter than the 0x48-byte output capacity.

Implemented response is `{land:{id,password},users:[{id,password},...]}`.
Returns existing deterministic island/caller credentials; other accounts receive
nil passwords as supported by the recovered client parser. Authenticated caller
must match my_user_id through the existing identity migration map. Island
credentials use the same derivation as land registration without requiring its
optional resident-binding cache. No island migration,
save modification, or user binding mutation occurs. Malformed/noninteger IDs,
duplicate/oversized arrays, absent caller, and unauthorized ownership are refused.

The first empty-body response was an incorrect hypothesis and was rolled back.
No further guessed response is deployed. Raw binaries/decompilations remain in
private notes and private notes, not source.
The historical recorded Switch/Ryujinx visits and nx-baas v0.12.57 do not show
this endpoint; why the current flow needs it is not yet established.

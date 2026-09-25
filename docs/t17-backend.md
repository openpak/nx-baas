# T17BE — Team17's backend, and what Moving Out 2 actually asks for

Researched 2026-09-25 from a Ryujinx run of **Moving Out 2** (`010065D018172000`, update
v327680 = 1.3.315) plus the game's own binary. Written down here because `t17.go` is the
capture spike that reads this protocol; when OpenPak answers for itself the code and this
file move to `servers/t17`.

## The observation

Moving Out 2's entire network footprint before it gave up, on a console redirected to
OpenPak for every Nintendo name:

```
resolve directory.t17service.com          -> 34.249.54.71, 34.241.133.245
TLS  connect 34.249.54.71:443
resolve pd5d8994ze.execute-api.eu-west-1.amazonaws.com -> 18.66.171.128, …
TLS  connect 18.66.171.128:443
(nothing else, ever)
```

Both went to the live internet: neither name was in the redirect ceiling, so `nn-sssl-dns`
passed them through. **No Photon name server was ever resolved** (`ns.photonengine.io`,
`*.exitgames.com`) and no UDP socket was opened. The game never reached Photon; it stopped
at Team17's gate. That is why nothing showed up on `openpak-photon`.

Since 2026-09-25 `.t17service.com` is in the signed ceiling (v2) and the switch platform
map, so the directory call lands on nx-baas instead — see `t17.go`.

## It is still a Photon Fusion title

From the update's exefs `main`: `Fusion.Common.dll`, `Fusion.Runtime`, `Fusion.Realtime.dll`,
`Fusion.Photon.Realtime`, `Photon3Unity3D.dll`, `MO2.Client.Runtime.dll`, `websocket-sharp.dll`.
So it is the same Fusion stack as Outbound — it is just gated behind Team17's own platform.

**No Photon AppId is baked into the build.** `resources.assets` holds a `PhotonAppSettings`
object and neither it nor any other extracted file contains a UUID-shaped string; the C# side
has `CustomPhotonAppSettings` / `customAppSettings`. The working hypothesis is that the AppId
arrives from the T17 backend (`/live/get` is the obvious carrier) — which would mean OpenPak
chooses it, and our own Photon server can accept whatever we hand out. Unverified.

## The T17BE SDK

`T17BE` is a **native C++ SDK statically linked into `main`**, not a C# library — its assert
strings carry the build paths `D:/work/68b937caf5bca218/core/source/T17BE_*.cpp`:

| Source file | What it owns |
|---|---|
| `T17BE_MainSystem.cpp` | player account (`InternalResponse_GetPlayerAccount`) |
| `T17BE_SessionSystem.cpp` | sessions / matchmaking |
| `T17BE_FriendSystem.cpp` | friends, invites, block list |
| `T17BE_StorageSystem.cpp` | cloud storage, pre-signed file URLs |
| `T17BE_LiveDataSystem.cpp` | live config |
| `T17BE_Transport.cpp` | the websocket transport below |
| `T17BE_Account.cpp`, `T17BE_UID.cpp` | roles (`client` / `server` / `service`), ids |

The C# side is `MO2.Client.Runtime` plus a Team17 crossplay layer
(`com.team17.xplay.overlay`, `GetXplayFriends`, `SendXplayFriendInviteByPlatformId`, …).

### Transport

`T17BE_Transport::PreInitialise` parses a JSON blob and **requires** these fields — this is
the shape of whatever the directory/API-gateway handshake returns:

- `token` (the auth token; `T17BE_Transport :: Initialise --> Missing Auth Token --> Bailing Out!!!`)
- `websocketUrl`
- `displayName` (split into a short and full name by the SDK)
- `platformId`
- a block list, parsed from the same "getToken response body"

After that everything is JSON **over one websocket**, framed with a required `header` per
message (`__ParseJSONObject --> No Header for Response - REQUIRED FOR RESPONSES!!`) and
matched to an original request. There is a re-auth and a reconnection dance:
`InternalResponse_ReAuth` (new `authToken`), `StartReconnection` → `reconnectionToken` →
`CompleteReconnection`. HTTP uses `Authorization: Bearer %s`. The SDK explicitly knows that
a 403 means "AWS returns this when the endpoint doesn't exist, or the backend rejected the
credentials", so the upstream is API Gateway.

### Route keys

The websocket route keys (and/or REST paths), read out of the decompressed `main`:

```
/player/get-account            /player/get-platform-accounts     /player/update-display-name
/sessions/create               /sessions/update                  /sessions/close
/sessions/leave                /sessions/kick-player             /sessions/grant-ownership
/sessions/send-invite          /sessions/accept-invite           /sessions/reject-invite
/sessions/withdraw-invite      /sessions/list-invites
/friends/send-friend-invite    /friends/accept-friend-invite     /friends/reject-friend-invite
/friends/withdraw-friend-invite /friends/remove-friend           /friends/get-friend-invites
/friends/get-friends-and-status /friends/subscribe-to-friend-status-updates
/friends/unsubscribe-to-friend-status-updates
/friends/block-player          /friends/unblock-player           /friends/get-blocked-players
/storage/get                   /storage/put                      /storage/delete
/storage/get-file-url
/live/get                      /live/put                         /live/patch
/websocket/go-online           /websocket/ping                   /websocket/start-reconnection
/websocket/complete-reconnection
/service/send-report-sns       /service/trigger-kill-switch
```

Known field names: `globalID` (the T17 player id), `displayNameFull` / `displayNameShort`,
`platformId`, `sessionId`, `websocketUrl`, `reconnectionToken`. The C# side has a literal
`auth/get-token`.

The player-facing failures are `error_connect_t17services`, `error_no_internet`,
`error_network_disconnected`, `error_dualmover_full`, `error_general` — `error_connect_t17services`
is what a blocked or refused gate shows.

## Reproducing the extraction

`hactool` and `nstool` both fail on this title: the **base** Program NCA uses `SparseStorage`
(nstool says so outright; hactool just says "Failed to read section"), so the RomFS cannot be
read without LibHac. `scratch/nspx` is a ~60-line LibHac console app that does it —
`nspx <base.nsp> <update.nsp|-> <romfs-path|--tree> <out>`; the update's Program NCA carries
the whole ExeFS and patches the base RomFS.

```sh
# exefs (hactool copes with the update NCA), then decompress the NSO
hactool -k prod.keys -t nca --titlekey=<tik bytes 0x180..0x18F> --exefsdir=uexefs <update program nca>
hactool -k prod.keys -t nso0 --uncompressed=main.bin uexefs/main   # 62 MB -> 151 MB
# romfs
dotnet scratch/nspx/bin/Release/net9.0/nspx.dll base.nsp update.nsp \
      /Data/Managed/Metadata/global-metadata.dat global-metadata.dat
```

`hactool` also rejects the current `~/.switch/prod.keys` outright (a 17-byte
`mariko_master_kek_source_05` aborts the whole load) — filter the file to even-length values
that are not 34 or 66 hex characters first.

Read strings from `main.bin`, never from `main`: the NSO segments are LZ4-compressed, and
the compressed copy is what makes every path look truncated (`/websocket/start-re`).
Il2CppDumper's auto mode does not find `CodeRegistration` in this build, so the C# side is
only readable as raw metadata strings so far.

Working files (not in any repo): `~/REPOS/Openpak/scratch/mo2/`.

## The live protocol, as captured 2026-09-25

The directory is one GET and its reply is the whole of the addressing:

```
GET directory.t17service.com/
  Api-Title: ProjectJourney   Api-Platform: nxswitch   Api-Tier: dev   Api-Version: 1
  User-Agent: UnityPlayer/2021.3.16f1 (UnityWebRequest/1.0, libcurl/7.64.1)

200 {"game":{"url":"http:///"},"xplayurl":"https://pd5d8994ze.execute-api.eu-west-1.amazonaws.com/prod/",
     "AllowXPlay":"1","ga":{"ga":"0"}}
```

Team17's own `game.url` is **empty** for this title and tier, which is why the retail game stops at
"An error has occurred connecting to T17 services" before it ever reaches Photon. Authentication
goes to the **xplay** URL, not `game.url`:

```
POST <xplayurl>auth/get-token
{"coreVersion":"1.0.6.0.0","platformId":"nintendo","deviceId":"nintendo-switch",
 "gameId":"ProjectJourney","authType":"nintendo-switch","displayName":"<user-a>",
 "nintendoSwitchAccessToken":"<JWT>"}
```

The JWT is one **OpenPak signed** (`kid: openpak-baas-key-1`, `sub` = the BAAS user id), so the
backend verifies its own token instead of asking Nintendo — the `servers/demonware` pattern.

### The get-token reply, read out of the binary

`T17BE_Transport::PreInitialise` is at **0x68f2c0** (update 1.3.315). It parses the root object
once (0x68f2f0), checks the root type at 0x68f310, then looks up keys in a fixed order **twice** —
a validation pass that can name what is missing, then a fill pass that cannot:

| key | pass | how the value is read |
|---|---|---|
| `websocketUrl` | both | string |
| `token` | both | string |
| `exp` | both | number — `ldr w8,[member+0x18]` → `str w8,[struct+0x108]` |
| `ttl` | both | number — → `struct+0x10c` |
| `displayName` | both | string (then split into full/short) |
| `globalPlayerId` | both | string |
| `role` | both | string, one of client / server / service |
| `blockList` | validation | **string holding JSON** — `__ParseInitialBlockList` (0x669acc) hands it to 0x670180, the same parser used on the whole reply |
| `deviceId` | validation | string |
| `platformId` | validation | string |
| `version` | **fill only** | string — assign helper 0x1f4b9f0 → `struct+0xf0` |

`version` has **no "Backend Missing required" string of its own**, so omitting it is accepted over
HTTP and then dropped in silence with no socket and no diagnostic. That cost several test rounds.

### Still unresolved

With all eleven fields correct the game still never dials the websocket — no DNS lookup for the
`websocketUrl` host at all. The native transport is therefore not the one refusing: the **C# layer
in front of it** never reaches the connection. That layer owns the socket (`websocket-sharp`,
`Sec-WebSocket-Key` and the `wss://{0}:{1}` format strings are all in the C# metadata) and models
the reply as `SimpleCorePreInitData` (`_websocketFullConnectionString _websocketUrl _role
_blockList _apiVersion ttl bAllOK bKillSwitchActive`), handing the native side the raw JSON as
`userStringyfiedJSONChunk`.

Reading it needs an IL2CPP dump, and Il2CppDumper's auto mode cannot find
`CodeRegistration`/`MetadataRegistration` in this build even at v6.7.46. The fingerprint is known —
`typeDefinitionsSize 0x177d38 / 120 = 12828` type definitions, a count `MetadataRegistration`
carries twice — but a scan of the raw file cannot confirm a candidate because **`.data` pointers in
an NSO are unrelocated on disk**. `scratch/nso_reloc.py` now does the relocation step: `MOD0` → `.dynamic` → `DT_RELA`, applying
**615,417** `R_AARCH64_RELATIVE` entries, after which `.data` pointers are real and pointer scans can
be validated. That was necessary but not sufficient — the registration structs still do not turn
up:

- No `{int32 count, pad, pointer}` run in `.data` or `.rodata` carries the type-definition count
  (12828) twice 0x10 apart, which is the `fieldOffsetsCount`/`typeDefinitionsSizesCount`
  signature of `Il2CppMetadataRegistration`. So either those counts differ in this build or the
  struct is not laid out as assumed.
- The NSO's dynamic symbol table is **imports only** (`nn::` SDK entries, value 0). IL2CPP is
  statically linked with nothing exported, so there is no `il2cpp_init` to walk from.

**Both dumpers are a dead end on this build, and neither is needed.** Il2CppDumper and
Il2CppInspectorRedux both fail to locate `CodeRegistration` ("No matches via data heuristics / no
matches via code heuristics"). The reason is now understood: the compiler **constant-folded**
`g_CodeRegistration->codeGenModules` into a direct address, so no pointer to the struct exists
anywhere in the image for a heuristic to find. Inspector also reports `Global offset:
0x0000007100000000` for an image whose segments live near `0x62e0000`, so it searches addresses
that do not exist.

None of that matters, because the two things a name→address map actually needs are reachable
without `CodeRegistration`:

1. **The code-gen module** is findable from its own name string: locate `"MO2.Client.Runtime.dll"`
   in `.rodata`, find the 8-byte slot in `.data` holding that address — that slot is the
   `Il2CppCodeGenModule`, whose fields are `{const char* moduleName; uint32 methodPointerCount;
   const Il2CppMethodPointer* methodPointers;}`. For this title: 3984 method pointers at
   `0x8f17ec0`, all in `.text`.
2. **The index** is the metadata token: `methodPointerIndex == (token & 0xFFFFFF) - 1`, and a
   method belongs to an assembly when its `declaringType` falls inside that image's
   `typeStart..typeStart+typeCount`. No type struct parsing is needed.

`scratch/il2cpp_methods.py` does this. It resolves **117,803 method addresses across 155
assemblies** — everything a dump would have given us for this purpose.

Two metadata facts worth keeping, both of which cost time by being assumed instead of measured:
`sizeof(Il2CppTypeDefinition)` here is **88**, not the 120 the field list implies, giving
**17493** type definitions — which is exactly the `fieldOffsetsCount`/`typeDefinitionsSizesCount`
in `MetadataRegistration` (`0x8ff0078`, found via the same route). And the documented
`Il2CppTypeDefinition` field order does **not** match this build: no `(u32 start, u16 count)` pair
satisfies `start[t+1] == start[t] + count[t]`, so do not trust it for `methodStart`.

### What this revealed about the C# gate, so far

The auth path lives in `Team17.CrossPlay.Core.dll` and `Team17.CrossPlay.Auth.dll`:

| Method | Address |
|---|---|
| `Team17.CrossPlay.Core::SendAuthRequest` | `0x23f6460` |
| `Team17.CrossPlay.Core::GetT17AuthJson` | `0x23f8130` |
| `Team17.CrossPlay.Core::BE_PreInitialise` | `0x23f8000` |
| `Team17.CrossPlay.Core::GetCorePreInitData` | `0x23f8050` |
| `Team17.CrossPlay.Auth::WaitingForResponse` | `0x4c25930` |
| `Team17.CrossPlay.Auth::GetFullResponse` / `GetGlobalPlayerID` | `0x4c25450` / `0x4c254d0` |

`BE_PreInitialise` is a **P/Invoke stub**: it marshals one managed string and calls native
`0x45a930`. The string is **not our HTTP response** — `GetT17AuthJson` (seven parameters, called
from `Core::<Update>b__142_0` and `Core::<_Authorise>b__0`) **rebuilds** the JSON from the C#
model. So the eleven fields `T17BE_Transport::PreInitialise` demands are produced by C#, and our
reply only has to satisfy *C#'s* parser — which likely explains why adding `version` to the HTTP
response changed nothing: if the C# model has no such field, it is dropped before native ever
sees it.

`WaitingForResponse` reads `exp` with `ldrsw` + `FromUnixTimeSeconds`, so that field is a signed
32-bit unix time and ours is in range.

**Next step:** read the C# field layout of the auth response class and the seven arguments at the
`GetT17AuthJson` call site (`0x23f9268`) to see exactly which response fields survive into the
native JSON. `scratch/addr2name.pkl` caches the address→name map for annotating disassembly.

## Tooling

`scratch/arm64xref.py` — reconstructs every ADRP+ADD pair in `.text` (740,061 of them here) to
answer "who references this string" and "which strings does this function reference". Anchor the
needle to its NUL boundary first: these error messages are suffixes of longer literals, and
xrefing the middle of a string finds nothing.

`scratch/unityfs.py` — UnityFS bundle unpacker, needed for the localisation tables. Moving Out 2
ships version 8 bundles with `BlockInfoNeedPaddingAtStart` (flags 0x243), where the block data is
16-byte aligned after the block info; Moving Out 1's are version 6 with neither.

## Open questions

1. What does `directory.t17service.com` actually answer, and does it still accept this
   console? The capture in `t17.go` exists to answer exactly that.
2. Does `/live/get` carry the Photon AppId (and region)?
3. The websocket is proxied but its frames are not logged yet — `httputil.ReverseProxy`
   splices the upgraded connection. Logging frames needs a hijacking RFC 6455 tee.
4. The API Gateway host (`pd5d8994ze.execute-api.eu-west-1.amazonaws.com`) is deliberately
   **not** redirected: `.execute-api.eu-west-1.amazonaws.com` is far too broad a family to
   put in the ceiling. Once OpenPak answers the directory itself it can return its own
   `websocketUrl` and the AWS name never needs to be redirected at all.

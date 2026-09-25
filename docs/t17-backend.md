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

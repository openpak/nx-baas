# nx-baas

BAAS (`*.baas.nintendo.com`) and Nintendo Account (`accounts.nintendo.com`) servers for a real
CFW Switch on the earlier stack. Backed by `openpak-account` (`/internal/*`) for identity,
friend codes and the friend graph; signs the same `openpak-baas-key-1` id_tokens the emulators
use, with the `openpak` claim, so Photon / NPLN / NEX servers see one identity per account.

Endpoints: `/1.0.0/application/token`, `/1.0.0/users` (+`/<id>`, `/<id>/link`, `generate_code`,
`device_accounts` presence patch), `/1.0.0/login`, `/1.0.0/federation`, `/1.0.0/certificates`,
`/2.0.0/users/<id>/friends`, `/2.0.0/friend_requests`, and the Nintendo-Account link flow
(`/connect/1.0.0/authorize`, `api/session_token`, `api/token`, `/2.0.0/users/me`).
Everything unknown is logged in full (`!! UNHANDLED`), which is how the undocumented parts
(friend invitations) get discovered.

Env: `NX_ADDR`, `NX_DATA`, `ACCOUNT_API`, `OPENPAK_SECRET`, `OPENPAK_ADMIN_KEY`,
`BAAS_SIGNING_KEY`, `BAAS_KID`, `NX_CA_DIR` (optional `ca.pem`/`ca.key` to sign the server cert).

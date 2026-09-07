# accountpb — vendored account-core contracts

A copy of `account/proto/openpak/account/v1` (generated stubs + the `.proto` sources they
come from). It is here because the account core is a separate private repo: a `replace
=> ../account` only resolves inside the local workspace, so CI and any clean checkout
could not build.

ponytail: a copy, not a shared module. When a third consumer appears (or these drift),
promote it to its own module — `github.com/openpak/account-proto` — and delete this
directory. To refresh today: re-copy the files from the account repo.

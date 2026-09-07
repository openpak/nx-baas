package main

import (
	"net/url"
)

// accountBackend is the identity source behind the BAAS surface. Two
// implementations exist:
//
//   - accountClient (account.go): the historical OpenPak stack client
//     (/internal/* HTTP + shared-secret nex tokens). Preserved unchanged so
//     the proven deployment keeps running during the migration.
//   - openpakBackend (openpak.go): the OpenPak account core (gRPC) with the
//     Switch identifier projection owned locally (PRD SW-01/SW-04).
//
// Selection is deployment configuration (ACCOUNT_BACKEND), never per-request.
type accountBackend interface {
	// Identity renders the full Switch-side identity for a PID: profile
	// fields plus friend projections (friends, incoming, sent requests).
	Identity(pid uint64) (*Identity, error)
	// Resolve looks up any account by friend code or BAAS user id.
	Resolve(q url.Values) (*Friend, error)
	// LoginPID verifies email + password for the "Link Nintendo Account"
	// flow and returns the canonical PID + username.
	LoginPID(email, password string) (uint64, string, error)
	// FriendRequest sends a request from one PID to another.
	FriendRequest(from, to uint64) error
	// FriendAccept accepts/declines a request addressed to pid.
	FriendAccept(pid, from uint64, accept bool) error
	// nexToken signs the "openpak" binding claim game servers verify.
	nexToken(pid uint64, username string) string
}

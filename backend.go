package main

import (
	"errors"
	"net/url"
)

// Errors the backends translate core failures into, so the HTTP layer maps
// them without knowing which backend answered. The core remains canonical;
// these only carry failure semantics across the interface (SOC-03).
var (
	errCoreInvalid     = errors.New("the core rejected the request")
	errCoreNotFound    = errors.New("the core does not know that account or request")
	errStateConflict   = errors.New("the relationship is not in the required state")
	errCoreUnavailable = errors.New("the core is unavailable")
	errCoreInternal    = errors.New("internal core error")
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
	// FriendRequest sends a request from one PID to another. A pending
	// request in the other direction is reported as errReversePending.
	FriendRequest(from, to uint64) error
	// FriendAccept accepts/declines a request addressed to pid. Declining
	// ends the pending request, which is the same core operation as removal.
	FriendAccept(pid, from uint64, accept bool) error
	// RemoveFriend ends a pending or accepted friendship from either side.
	RemoveFriend(pid, other uint64) error
	// Block/Unblock commit durable directional blocks in the core, which owns
	// the enforcement every other adapter sees.
	Block(pid, other uint64) error
	Unblock(pid, other uint64) error
	// nexToken signs the "openpak" binding claim game servers verify.
	nexToken(pid uint64, username string) string
	// nexSigningKey is the key nexToken signs with, so the game API can verify a
	// token it (or the account server) minted without a round trip.
	nexSigningKey() []byte
	// friendCodeForAccount answers the website, which mints no codes and holds
	// none: the core knows an account is linked, not what its code is.
	friendCodeForAccount(accountID string) (string, bool)

	// accountForFriendCode is the reverse, and the one the website needs to
	// add a friend by code. The core's "switch" link subject is the BAAS user
	// id, never the friend code, so a lookup against the core can only miss.
	accountForFriendCode(code string) (string, bool)
	// RegenerateFriendCode mints a new code for a user who asked for one from
	// the console (POST /1.0.0/users/<id>/generate_code).
	RegenerateFriendCode(pid uint64) error
}

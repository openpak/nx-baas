// The record store behind Penne delivery.
//
// A notification on 22.5.0 is not a message, it is a record. The console keeps
// four of them per account — c-appearance, c-friends, c-settings, c-storage —
// opens every connection by offering a SHA-1 digest of each (RootHash), and
// accepts changes as PutRecord{name, value}, storing the pair and announcing
// the name to whichever sysmodule subscribes to it. For c-friends that
// subscriber is the friends module, which is what makes a console refetch its
// friend list (docs/penne-protocol.md §4d, §4e).
//
// So this is the delivery mechanism: write the account's c-friends record and
// the console reacts. What we keep here is the last value we wrote per account
// and its digest, so the next sync can answer truthfully about the records we
// do own instead of mirroring the console's back at it.
package main

import (
	"crypto/sha1"
	"sync"
)

// Record namespaces the console offers digests for [runtime capture,
// 2026-09-12], and the topics that hang off them.
//
// A RootHash entry names a namespace; a record is named for the topic a module
// subscribed to, which is a dotted path under one. The friends module makes
// exactly one subscription in its whole init —
// FUN_001eaa30("c-friends.inv.subsTypes", "friend", 6) at 0x17bd24 — so that
// is the name a notification for it has to be written under. The namespace
// digest covers whatever hangs below it, by an aggregation this server cannot
// reproduce, which is why a sync still answers with the console's own digests.
const (
	namespaceFriends    = "c-friends"
	namespaceAppearance = "c-appearance"
	namespaceSettings   = "c-settings"
	namespaceStorage    = "c-storage"

	// recordFriends is the topic the friends module subscribes to, and so the
	// record a friend notification is written to [firmware, 0x17bd24].
	recordFriends = "c-friends.inv.subsTypes"
)

// penneRecordStore holds what this server has written, per account. It is
// deliberately not a mirror of the console's own store: the console is
// authoritative for everything we have never written, and a sync answers with
// the console's own digest for those.
type penneRecordStore struct {
	mu   sync.Mutex
	byID map[string]map[string][]byte // user id -> record name -> value
}

func newPenneRecordStore() *penneRecordStore {
	return &penneRecordStore{byID: map[string]map[string][]byte{}}
}

// Put remembers the value written to one of an account's records.
func (s *penneRecordStore) Put(userID, name string, value []byte) {
	if userID == "" || name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID[userID] == nil {
		s.byID[userID] = map[string][]byte{}
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.byID[userID][name] = cp
}

// Digest is the SHA-1 of a record we have written, and whether we have one.
// The console's RootHash carries twenty bytes per name, which is the width of
// a SHA-1 [runtime capture].
func (s *penneRecordStore) Digest(userID, name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.byID[userID][name]
	if !ok {
		return nil, false
	}
	sum := sha1.Sum(value)
	return sum[:], true
}

// records is the process-wide store; one per server, created on first use so a
// zero-value server (the tests') works without setup.
func (s *server) records() *penneRecordStore {
	s.recordsOnce.Do(func() { s.recordStore = newPenneRecordStore() })
	return s.recordStore
}

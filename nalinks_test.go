package main

import "testing"

// The Add Friend applet never asks FRS for type=nintendo_3ds or
// nintendo_network_id, and an empty links object on users/me is the only
// precondition we were visibly failing. The account module reads
// $.links.nintendoNetwork.{id,createdAt}, so both have to be there and the id
// has to be a string like every other links.*.id we serve.
func TestNALinksAdvertisesANintendoNetworkLink(t *testing.T) {
	links := naLinks(&Identity{PID: 42, NaID: "aabbccdd11223344"})
	nn, ok := links["nintendoNetwork"].(map[string]any)
	if !ok {
		t.Fatalf("no nintendoNetwork link: %v", links)
	}
	if id, ok := nn["id"].(string); !ok || id == "" {
		t.Errorf("id = %#v, want a non-empty string", nn["id"])
	}
	if _, ok := nn["createdAt"].(int64); !ok {
		t.Errorf("createdAt = %#v, want an integer", nn["createdAt"])
	}
}

// An account we know nothing about must not be told it has a linked NNID: the
// id would be "0", and a link to nothing is worse than no link.
func TestNALinksIsEmptyWithoutAnIdentity(t *testing.T) {
	for name, id := range map[string]*Identity{"nil": nil, "zero PID": {}} {
		if got := naLinks(id); len(got) != 0 {
			t.Errorf("%s identity got %v, want no links", name, got)
		}
	}
}

// users/me serves the account's own address and its masked screenName, as a Nintendo Account
// does; the captured sample's placeholders only when there is no address.
func TestNAAddress(t *testing.T) {
	for in, want := range map[string][2]string{
		"player@example.org": {"player@example.org", "pl•••@e••••"},
		"a@b.c":              {"a@b.c", "a•••@b••••"},
		"":                   {"player@example.com", "ne•••@e••••"},
		"not-an-address":     {"player@example.com", "ne•••@e••••"},
	} {
		if email, screen := naAddress(in); email != want[0] || screen != want[1] {
			t.Errorf("naAddress(%q) = %q, %q; want %q, %q", in, email, screen, want[0], want[1])
		}
	}
}

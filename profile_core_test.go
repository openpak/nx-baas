package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"nx-baas/internal/identity"

	accountv1 "github.com/openpak/account-api/openpak/account/v1"
)

type recordingIdentity struct {
	fakeIdentity
	got *accountv1.UpdatePublicProfileRequest
}

func (r *recordingIdentity) UpdatePublicProfile(_ context.Context, in *accountv1.UpdatePublicProfileRequest, _ ...grpc.CallOption) (*accountv1.GetAccountResponse, error) {
	r.got = in
	return &accountv1.GetAccountResponse{}, nil
}

// A console's name and country edits reach the core under the account the PID
// belongs to, and the backend says which of them the core took (card #131).
func TestUpdateProfileGoesToTheCoreFirst(t *testing.T) {
	f := newFakeCore()
	rec := &recordingIdentity{fakeIdentity: fakeIdentity{f: f}}
	b := identity.NewOpenpakBackendWithClients(t.TempDir(), rec, fakeLinks{f: f}, fakeSocial{f: f}, []byte(strings.Repeat("k", 32)))
	f.addAccount("acc-1", "Before", "correct horse battery")
	res, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistration{}
	b.Register = reg
	nick, country := "After", "SE"
	nOK, cOK, err := b.UpdateProfile(res.PID, &nick, &country)
	if err != nil || !nOK || !cOK {
		t.Fatalf("update = %v %v %v", nOK, cOK, err)
	}
	if reg.got.GetAccountId() != "acc-1" || reg.got.GetDisplayName() != "After" {
		t.Fatalf("name went to %+v", reg.got)
	}
	if rec.got.GetAccountId() != "acc-1" || rec.got.GetCountry() != "SE" || rec.got.DisplayName != nil {
		t.Fatalf("country went to %+v", rec.got)
	}
	// Nothing to write is nothing sent.
	rec.got = nil
	if nOK, cOK, err := b.UpdateProfile(res.PID, nil, nil); err != nil || nOK || cOK || rec.got != nil {
		t.Fatal("an empty edit reached the core")
	}
	var _ identity.ProfileWriter = b
}

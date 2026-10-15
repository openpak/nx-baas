package main

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	accountv1 "nx-baas/accountpb"
)

type fakeRegistration struct {
	accountv1.RegistrationClient
	got *accountv1.SetDisplayNameRequest
}

func (r *fakeRegistration) SetDisplayName(_ context.Context, in *accountv1.SetDisplayNameRequest, _ ...grpc.CallOption) (*accountv1.SetDisplayNameResponse, error) {
	r.got = in
	return &accountv1.SetDisplayNameResponse{}, nil
}

// A name chosen on a console reaches the core under the account the PID belongs to.
func TestSetNicknameGoesToTheCore(t *testing.T) {
	b, f := newTestBackend(t)
	f.addAccount("acc-1", "Before", "correct horse battery")
	pid, _, err := b.LoginPID("acc-1", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SetNickname(pid, "After"); err == nil {
		t.Fatal("no registration client: want an error, not a silent drop")
	}
	reg := &fakeRegistration{}
	b.register = reg
	if err := b.SetNickname(pid, "After"); err != nil {
		t.Fatal(err)
	}
	if reg.got.GetAccountId() != "acc-1" || reg.got.GetDisplayName() != "After" || reg.got.GetCallerNamespace() != b.namespace {
		t.Fatalf("core was sent %+v", reg.got)
	}
	if err := b.SetNickname(pid+1, "Nobody"); err == nil {
		t.Fatal("unknown PID must fail")
	}
}

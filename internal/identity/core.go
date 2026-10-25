package identity

import (
	"context"
	accountv1 "github.com/openpak/account-api/openpak/account/v1"
)

// AccountStatus is the core's status for an account (the ban check's source).
func (b *OpenpakBackend) AccountStatus(ctx context.Context, accountID string) (accountv1.AccountStatus, error) {
	res, err := b.IdentityClient.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID})
	if err != nil {
		return accountv1.AccountStatus_ACCOUNT_STATUS_UNSPECIFIED, err
	}
	return res.GetStatus(), nil
}

// CheckInteraction on the openpak backend consults the core's Social service.
func (b *OpenpakBackend) CheckInteraction(ctx context.Context, actorAccountID, targetAccountID string) (bool, string, error) {
	res, err := b.Social.CheckInteraction(ctx, &accountv1.CheckInteractionRequest{
		ActorId: actorAccountID, TargetId: targetAccountID, Kind: accountv1.InteractionKind_INTERACTION_KIND_INVITE,
	})
	if err != nil {
		return false, "", err
	}
	if !res.GetAllowed() {
		return false, res.GetReason().String(), nil
	}
	return true, "", nil
}

// ResolveSession on the openpak backend consults the core's session registry.
// A session registered without a title matches any title for this purpose:
// the core's title field is optional metadata, and its absence must not read
// as "the sender is gone".
func (b *OpenpakBackend) ResolveSession(ctx context.Context, accountID, titleID string) (bool, error) {
	res, err := b.Sessions.ResolveSession(ctx, &accountv1.ResolveSessionRequest{AccountId: accountID, TitleId: titleID})
	if err != nil {
		return false, err
	}
	return res.GetSessionId() != "", nil
}

// AccountForBaas resolves the core account behind a BAAS user id.
func (b *OpenpakBackend) AccountForBaas(baasUID string) (string, bool) {
	b.Proj.Mu.Lock()
	defer b.Proj.Mu.Unlock()
	id, ok := b.Proj.ByBaas[baasUID]
	return id, ok
}

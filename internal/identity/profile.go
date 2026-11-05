package identity

import (
	"context"
	"errors"
	"time"

	accountv1 "github.com/openpak/account-api/openpak/account/v1"
)

// CoreProfile is the slice of a core account the Switch adapter caches next to a
// BAAS user: what the console is shown as nickname, country and birthday, and the
// profile_version a refresh compares to decide whether anything moved.
type CoreProfile struct {
	DisplayName string
	Country     string
	Birthday    string
	Version     uint64
}

// ProfileWriter is the write side of the core's profile: a console edit goes to the
// core first, so the website, the app and every other network see it, and the BAAS
// record only keeps a copy when the core refused.
type ProfileWriter interface {
	// UpdateProfile writes the given fields (nil = untouched) to the account behind pid.
	// It reports which of them the core accepted.
	UpdateProfile(pid uint64, nickname, country *string) (nicknameOK, countryOK bool, err error)
	// CoreProfile reads the account's profile for a cache refresh.
	CoreProfile(accountID string) (CoreProfile, error)
}

var _ ProfileWriter = (*OpenpakBackend)(nil)

func (b *OpenpakBackend) UpdateProfile(pid uint64, nickname, country *string) (nicknameOK, countryOK bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accountID, e := b.accountForPID(ctx, pid)
	if e != nil {
		return false, false, e
	}
	var errs []error
	if nickname != nil {
		if b.Register == nil {
			errs = append(errs, errors.New("no registration client"))
		} else if _, e := b.Register.SetDisplayName(ctx, &accountv1.SetDisplayNameRequest{
			CallerNamespace: b.Namespace, AccountId: accountID, DisplayName: *nickname}); e != nil {
			errs = append(errs, e)
		} else {
			nicknameOK = true
		}
	}
	if country != nil {
		if _, e := b.IdentityClient.UpdatePublicProfile(ctx, &accountv1.UpdatePublicProfileRequest{
			AccountId: accountID, Country: country}); e != nil {
			errs = append(errs, e)
		} else {
			countryOK = true
		}
	}
	return nicknameOK, countryOK, errors.Join(errs...)
}

func (b *OpenpakBackend) CoreProfile(accountID string) (CoreProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	acc, err := b.IdentityClient.GetAccount(ctx, &accountv1.GetAccountRequest{AccountId: accountID})
	if err != nil {
		return CoreProfile{}, err
	}
	return CoreProfile{DisplayName: acc.GetDisplayName(), Country: acc.GetCountry(), Birthday: acc.GetBirthday(), Version: acc.GetProfileVersion()}, nil
}

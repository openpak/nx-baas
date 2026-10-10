package main

// Digital bundles: applications a title brings with it, redeemed per console.
//
// A catalog title may declare a bundle (ShopTitle.Bundle): buying or owning title X brings
// titles Y and Z. The console asks about it on beach with three NIM calls
// [firmware, nim 22.5.0; docs/native-shop.md "P2 leftovers"]:
//
//   - GET /v1/devices/redeemed_status (0x234540, reply handler 0x234a50): the reply must
//     carry $.digital_bundle and $.pre_install as booleans (else 0x15489). The handler
//     stores each bool as sent, and 0x234540 then sets bit 0 of the caller's flags when
//     digital_bundle is false and bit 1 when pre_install is false. So the booleans read
//     "redeemed", and false is the "not yet redeemed" signal the caller acts on. The
//     request carries the device token only.
//   - GET /v1/devices/digital_bundle/contents?shop_id=4 (0x234bd0, element handler vtable
//     0x328ed8): $.contents[] (at most 64) of {application_id (hex string, parsed
//     base-16), is_upgrade_edition (bool), redeemed (bool)}, and a top-level $.redeemed
//     bool. Device token only.
//   - POST /v1/devices/target/set and /target/clear (task 0x237f30; a flag at +0x90
//     picks set or clear, URL builders 0x1ed4c0 / 0x1ed570): device token plus
//     "Authorization: Bearer <id token>" for the user at +0x80, no request body, and a
//     success reply that is not read. This is the only account-bearing call in the
//     family, which makes it the redemption: the user the console picked becomes the
//     target of the device's bundle. qlaunch's "StReceiveDigitalBundle" and the account
//     picker's "ActSelect_DigitalBundleDetail_DlgBodyOwner/Other" strings fit that
//     reading; Nintendo's public FAQ describes the same act ("the game will be claimed by
//     the Nintendo Account you selected").
//
// What OpenPak makes of it: a device has a bundle when an account linked to it (beach
// link) owns a catalog title with a bundle. target/set grants the presenting account an
// entitlement for every unredeemed bundled application (the same row a purchase makes,
// so edge tokens and atum serve it), and records the redemption per device. target/clear
// undoes the presenting account's redemptions on that device and revokes only the rows
// those redemptions created. Unverified on hardware: the meaning of target/clear, the
// reply bodies of target/{set,clear}, and when qlaunch/ns choose to call them.

import (
	"log"
	"net/http"
	"nx-baas/redact"
	"sort"
	"time"
)

// BundleRedemption is one bundled application redeemed on one device.
type BundleRedemption struct {
	DeviceID      string `json:"device_id"`
	AccountID     string `json:"account_id"` // the account the redemption granted it to
	ParentID      string `json:"parent_title_id"`
	ApplicationID string `json:"application_id"`
	// Granted says the redemption created the account's entitlement (the account did
	// not already hold one), so clearing the redemption may revoke it.
	Granted    bool  `json:"granted"`
	RedeemedAt int64 `json:"redeemed_at"`
}

// bundleEntry is one element of a device's bundle as the console sees it.
type bundleEntry struct {
	ParentID         string
	ApplicationID    string
	IsUpgradeEdition bool
	Redeemed         bool
}

// maxBundleContents is NIM's own bound on $.contents [nim 0x234bd0: 0x40].
const maxBundleContents = 64

// deviceBundle lists the bundled applications a device is entitled to: the bundles of the
// published titles its linked accounts own, restricted to bundled applications this store
// publishes (anything else could never install). One element per application id.
func (s *shopState) deviceBundle(deviceID string) []bundleEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if deviceID == "" {
		return nil
	}
	accounts := map[string]bool{}
	for _, l := range s.Links.Links {
		if l.DeviceID == deviceID {
			accounts[l.AccountID] = true
		}
	}
	parents := map[string]bool{}
	for _, e := range s.Entitlements {
		if accounts[e.AccountID] && e.Status == "active" {
			parents[e.TitleID] = true
		}
	}
	ids := make([]string, 0, len(parents))
	for id := range parents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	seen := map[string]bool{}
	var out []bundleEntry
	for _, pid := range ids {
		t := s.Catalog[pid]
		if t == nil || t.Unpublished {
			continue
		}
		for _, it := range t.Bundle {
			if seen[it.ApplicationID] || len(out) >= maxBundleContents {
				continue
			}
			if bt := s.Catalog[it.ApplicationID]; bt == nil || bt.Unpublished {
				continue
			}
			seen[it.ApplicationID] = true
			out = append(out, bundleEntry{
				ParentID: pid, ApplicationID: it.ApplicationID, IsUpgradeEdition: it.IsUpgradeEdition,
				Redeemed: s.redeemedLocked(deviceID, it.ApplicationID) != nil,
			})
		}
	}
	return out
}

func (s *shopState) redeemedLocked(deviceID, appID string) *BundleRedemption {
	for _, r := range s.Redemptions {
		if r.DeviceID == deviceID && r.ApplicationID == appID {
			return r
		}
	}
	return nil
}

// bundleRedeemed is the top-level answer: there is a bundle and all of it is redeemed.
func bundleRedeemed(b []bundleEntry) bool {
	if len(b) == 0 {
		return false
	}
	for _, e := range b {
		if !e.Redeemed {
			return false
		}
	}
	return true
}

// redeemBundle grants the account every unredeemed application of the device's bundle and
// records the redemptions. Returns the application ids it redeemed now.
func (s *shopState) redeemBundle(deviceID, accountID, baasUserID string) []string {
	var done []string
	for _, e := range s.deviceBundle(deviceID) {
		if e.Redeemed {
			continue
		}
		had := s.entitlementFor(accountID, e.ApplicationID)
		granted := had == nil || had.Status != "active"
		ent, _, err := s.acquire(accountID, baasUserID, e.ApplicationID, deviceID, 0)
		if err != nil {
			log.Printf("[shop] bundle: %s for %s on %s: %v", e.ApplicationID, redact.Tag(accountID), redact.Tag(deviceID), redact.Err(err))
			continue
		}
		s.mu.Lock()
		if granted {
			ent.Source = "bundle:" + e.ParentID
		}
		s.Redemptions = append(s.Redemptions, &BundleRedemption{
			DeviceID: deviceID, AccountID: accountID, ParentID: e.ParentID, ApplicationID: e.ApplicationID,
			Granted: granted, RedeemedAt: time.Now().Unix(),
		})
		s.save()
		s.mu.Unlock()
		done = append(done, e.ApplicationID)
	}
	return done
}

// clearBundle removes the device's redemptions (the account's only, when one is named) and
// revokes the entitlements those redemptions created. A purchase is never revoked here.
func (s *shopState) clearBundle(deviceID, accountID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cleared []string
	kept := s.Redemptions[:0]
	for _, r := range s.Redemptions {
		if r.DeviceID != deviceID || (accountID != "" && r.AccountID != accountID) {
			kept = append(kept, r)
			continue
		}
		cleared = append(cleared, r.ApplicationID)
		if !r.Granted {
			continue
		}
		for _, e := range s.Entitlements {
			if e.AccountID == r.AccountID && e.TitleID == r.ApplicationID && e.Source == "bundle:"+r.ParentID && e.Status == "active" {
				e.Status = "revoked"
				e.UpdatedAt = time.Now().Unix()
			}
		}
	}
	s.Redemptions = kept
	if len(cleared) > 0 {
		s.save()
	}
	return cleared
}

// beachBundle answers the four digital-bundle routes; false when p is not one of them.
func (s *server) beachBundle(w http.ResponseWriter, r *http.Request, p string) bool {
	device := s.deviceIdentity(r)
	switch p {
	case "/v1/devices/redeemed_status":
		b := s.shop.deviceBundle(device)
		redeemed := bundleRedeemed(b)
		// pre_install stays false: OpenPak never ships software pre-installed, so there
		// is nothing a console could have redeemed that way (the literal answer).
		log.Printf("[shop] beach %s %s device=%s -> digital_bundle=%v (%d bundled), pre_install=false",
			r.Method, redact.Path(p), redact.Tag(device), redeemed, len(b))
		writeJSON(w, 200, map[string]any{"digital_bundle": redeemed, "pre_install": false})
	case "/v1/devices/digital_bundle/contents":
		b := s.shop.deviceBundle(device)
		contents := make([]map[string]any, 0, len(b))
		for _, e := range b {
			contents = append(contents, map[string]any{
				"application_id": e.ApplicationID, "is_upgrade_edition": e.IsUpgradeEdition, "redeemed": e.Redeemed,
			})
		}
		log.Printf("[shop] beach %s %s shop_id=%q device=%s -> %d bundled application(s)",
			r.Method, redact.Path(p), redact.IDs(r.URL.Query().Get("shop_id")), redact.Tag(device), len(contents))
		writeJSON(w, 200, map[string]any{"contents": contents, "redeemed": bundleRedeemed(b)})
	case "/v1/devices/target/set":
		account, baasUser := s.shopPrincipal(r)
		if device == "" || account == "" {
			log.Printf("[shop] beach %s %s: device=%s account=%s -> 401 (redemption needs both)", r.Method, redact.Path(p), redact.Tag(device), redact.Tag(account))
			beachErr(w, 401, "1002", "device and account identity required")
			return true
		}
		// The redeeming account acts on this console from now on: link it, so NIM's
		// device-token rights and edge-token calls resolve to it.
		s.shop.linkDevice(device, account, baasUser)
		done := s.shop.redeemBundle(device, account, baasUser)
		log.Printf("[shop] beach %s %s device=%s account=%s -> redeemed %v (reply shape unverified: NIM does not read it)",
			r.Method, redact.Path(p), redact.Tag(device), redact.Tag(account), done)
		w.WriteHeader(http.StatusOK)
	case "/v1/devices/target/clear":
		if device == "" {
			beachErr(w, 401, "1002", "device identity required")
			return true
		}
		account, _ := s.shopPrincipal(r)
		cleared := s.shop.clearBundle(device, account)
		log.Printf("[shop] beach %s %s device=%s account=%s -> cleared %v (meaning unverified on hardware)",
			r.Method, redact.Path(p), redact.Tag(device), redact.Tag(account), cleared)
		w.WriteHeader(http.StatusOK)
	default:
		return false
	}
	return true
}

package main

// The penne API: the push state other services read and drive, served by whichever process
// holds it -- this one until the Penne cut-over, nx-penne after (docs/service-split.md). Both
// answer the same paths with the same JSON (github.com/openpak/nx-common/nxapi), so a caller
// only changes its base URL when Penne moves.
//
// Keyed like the identity API: no key configured, no caller.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// penneRegistrations serves GET /internal/penne/registrations/{penne_id}: whether the
// registration is live, the user it was made for and every user signed in on that console.
// It is what nx-shop's pushmo /p/<penne id> resolves accounts through.
func (s *server) penneRegistrations(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/internal/penne/registrations/")
	if id == "" || strings.Contains(id, "/") || r.Method != http.MethodGet {
		apiErr(w, http.StatusNotFound, "no such route")
		return
	}
	ps := s.notifStore()
	out := map[string]any{"penne_id": id, "live": false, "user_id": "", "users": []string{}}
	if a := ps.AssocIfLive(id); a != nil {
		out["live"], out["user_id"] = true, a.UserID
		if users := ps.UsersOn(id); users != nil {
			out["users"] = users
		}
	}
	writeJSON(w, 200, out)
}

// penneInternal serves the rest of /internal/penne while Penne is served here: the calls
// the core makes into Penne (penne_link.go), as other services make them. nx-penne answers
// the same routes the same way.
func (s *server) penneInternal(w http.ResponseWriter, r *http.Request) {
	if !identityAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		apiErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		DeviceID          string         `json:"device_id"`
		UserID            string         `json:"user_id"`
		DeviceAccountID   string         `json:"device_account_id"`
		Service           string         `json:"service"`
		DeviceToken       string         `json:"device_token"`
		ID                string         `json:"id"`
		Kind              string         `json:"kind"`
		Payload           map[string]any `json:"payload"`
		Topic             string         `json:"topic"`
		Name              string         `json:"name"`
		Receivers         string         `json:"receivers"`
		Body              string         `json:"body"`
		NotificationToken string         `json:"notification_token"`
		PenneID           string         `json:"penne_id"`
		DauthUser         string         `json:"dauth_user"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "body is not JSON")
		return
	}
	switch p := strings.TrimPrefix(r.URL.Path, "/internal/penne"); {
	case p == "/consoles" && in.DeviceID != "" && in.UserID != "":
		s.notifStore().BindConsole(in.DeviceID, in.UserID)
		w.WriteHeader(http.StatusNoContent)
	case p == "/push-channels" && in.UserID != "":
		s.notifStore().RecordPushChannel(in.UserID, in.DeviceAccountID, in.Service, in.DeviceToken, time.Now())
		w.WriteHeader(http.StatusNoContent)
	case p == "/notifications" && in.UserID != "" && in.Kind != "":
		res := s.submitNotification(PenneDelivery{ID: in.ID, UserID: in.UserID, Kind: in.Kind, Payload: in.Payload}, true)
		writeJSON(w, 200, map[string]any{"accepted": res.Accepted, "duplicate": res.Duplicate, "outcome": string(res.Outcome), "id": res.ID})
	case p == "/topic-messages" && in.Topic != "" && in.Name != "":
		subs, n := s.localTopicMessage(strings.ToLower(in.Topic), in.Name, in.Receivers, in.Body)
		writeJSON(w, 200, map[string]any{"subscribers": subs, "delivered": n})
	case p == "/token-bindings" && in.NotificationToken != "" && in.UserID != "":
		writeJSON(w, 200, map[string]any{"bound": s.localBindToken(in.NotificationToken, in.UserID)})
	case p == "/device-messages" && (in.PenneID != "" || in.DauthUser != "") && in.Name != "":
		id, n := s.localDeviceMessage(in.PenneID, in.DauthUser, in.Name, in.Receivers, in.Body)
		writeJSON(w, 200, map[string]any{"penne_id": id, "connections": n})
	case strings.HasPrefix(p, "/users/") && strings.HasSuffix(p, "/close"):
		n := 0
		if s.penneHub != nil {
			n = s.penneHub.closeUser(strings.TrimSuffix(strings.TrimPrefix(p, "/users/"), "/close"))
		}
		writeJSON(w, 200, map[string]any{"closed": n})
	default:
		apiErr(w, http.StatusNotFound, "no such penne route, or a required field is missing")
	}
}

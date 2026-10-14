package main

import (
	"net/http/httptest"
	"testing"
)

func TestAcbaaEmigrationRecoveredContract(t *testing.T) {
	s := testServer(t)
	s.acbaaUserLand = map[uint64]uint64{42: 99, 43: 99, 44: 100}
	request := map[string]any{"land_id": uint64(99), "my_user_id": uint64(42), "user_ids": []any{uint64(42), uint64(43), uint64(44)}}
	r := httptest.NewRequest("POST", "https://api.hac.lp1.acbaa.srv.nintendo.net/api/v1/emigrations", nil)
	r.Header.Set("Authorization", "Bearer "+acbaaMintToken(42))
	w := httptest.NewRecorder()
	s.acbaa(w, r, msgpack(request))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	land := doc["land"].(map[string]any)
	if msgpackReadUintOf(land["id"]) != 99 || land["password"] != acbaaLandPassword(99) {
		t.Fatal("island credentials mismatch")
	}
	users := doc["users"].([]any)
	if len(users) != 3 || users[0].(map[string]any)["password"] != acbaaUserPassword(42) {
		t.Fatal("missing caller credential")
	}
	for _, user := range users[1:] {
		if user.(map[string]any)["password"] != nil {
			t.Fatal("another account's credential disclosed")
		}
	}
	if s.acbaaUserLand[42] != 99 || s.acbaaUserLand[44] != 100 {
		t.Fatal("credential exchange changed ownership")
	}
}

func TestAcbaaEmigrationRejectsInvalidOwnershipAndShapes(t *testing.T) {
	s := testServer(t)
	s.acbaaUserLand = map[uint64]uint64{42: 99}
	for _, tc := range []struct {
		name   string
		body   map[string]any
		status int
	}{
		{"wrong user", map[string]any{"land_id": uint64(99), "my_user_id": uint64(43), "user_ids": []any{uint64(43)}}, 403},
		{"negative island", map[string]any{"land_id": int64(-1), "my_user_id": uint64(42), "user_ids": []any{uint64(42)}}, 400},
		{"missing caller", map[string]any{"land_id": uint64(99), "my_user_id": uint64(42), "user_ids": []any{uint64(43)}}, 400},
		{"duplicate users", map[string]any{"land_id": uint64(99), "my_user_id": uint64(42), "user_ids": []any{uint64(42), uint64(42)}}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/v1/emigrations", nil)
			r.Header.Set("Authorization", "Bearer "+acbaaMintToken(42))
			w := httptest.NewRecorder()
			s.acbaa(w, r, msgpack(tc.body))
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
		})
	}
}

func TestAcbaaDepartureMigratedPlayerWithoutIslandBinding(t *testing.T) {
	s := testServer(t)
	s.acbaaUIDMap = map[uint64]uint64{43: 42}
	r := httptest.NewRequest("POST", "/api/v1/emigrations", nil)
	r.Header.Set("Authorization", "Bearer "+acbaaMintToken(42))
	w := httptest.NewRecorder()
	s.acbaa(w, r, msgpack(map[string]any{"land_id": uint64(99), "my_user_id": uint64(43), "user_ids": []any{uint64(43)}}))
	if w.Code != 200 {
		t.Fatalf("migrated player with no cached binding refused: %d", w.Code)
	}
	v, err := msgpackDecode(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	user := v.(map[string]any)["users"].([]any)[0].(map[string]any)
	if msgpackReadUintOf(user["id"]) != 43 || user["password"] != acbaaUserPassword(43) {
		t.Fatal("saved identity's credentials changed")
	}
	if len(s.acbaaUserLand) != 0 {
		t.Fatal("departure created an island binding")
	}
}

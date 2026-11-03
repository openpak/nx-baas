package pgdoc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Needs a Postgres: NX_BAAS_TEST_DATABASE_URL. Skipped without it.
func TestRestartSeesState(t *testing.T) {
	url := os.Getenv("NX_BAAS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("NX_BAAS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	Default = db
	defer func() { Default = nil }()
	db.pool.Exec(ctx, `DELETE FROM nxbaas_docs WHERE key IN ('t-a.json','t-b.json')`)

	dir := t.TempDir()
	legacy := filepath.Join(dir, "t-a.json")
	os.WriteFile(legacy, []byte(`{"n":1}`), 0o600)
	b, ok := Read(legacy) // imports the file
	if !ok || string(b) != `{"n": 1}` {
		t.Fatalf("import: %q %v", b, ok)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("legacy file must stay")
	}
	os.WriteFile(legacy, []byte(`{"n":2}`), 0o600) // file changes are ignored once imported
	if b, _ := Read(legacy); string(b) != `{"n": 1}` {
		t.Fatalf("second read: %q", b)
	}
	p := filepath.Join(dir, "t-b.json")
	if _, ok := Read(p); ok {
		t.Fatal("missing doc must not exist")
	}
	if err := Write(p, []byte(`{"x":[1,2]}`)); err != nil {
		t.Fatal(err)
	}
	// a new instance on the same DB sees it
	db2, _ := Open(ctx, url)
	defer db2.Close()
	Default = db2
	if b, ok := Read(p); !ok || string(b) != `{"x": [1, 2]}` {
		t.Fatalf("restart: %q %v", b, ok)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("DB mode must not write the file")
	}
}

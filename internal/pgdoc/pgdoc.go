// Package pgdoc keeps nx-baas's player state in Postgres: one table, one row per
// document (key + jsonb), saved in one statement exactly where the JSON file used to
// be written. Owner rule 2026-11-03: Postgres is the store so one database backup
// covers everything.
//
// Default is set once by main (NX_BAAS_DATABASE_URL is required there). While it is
// nil the helpers fall back to the old atomic file write, which is how unit tests
// that only need a temp directory keep running.
//
// On the first read of a key the DB does not have yet, the legacy file (when it
// exists) is imported. The file is never changed or removed.
package pgdoc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct{ pool *pgxpool.Pool }

// Default is the process-wide store; nil means file mode.
var Default *DB

const schema = `CREATE TABLE IF NOT EXISTS nxbaas_docs (
  key        text PRIMARY KEY,
  doc        jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
)`

// Open connects (small pool) and creates the table.
func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(c, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &DB{pool: pool}, nil
}

func (d *DB) Close() { d.pool.Close() }

func (d *DB) get(key string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var b []byte
	err := d.pool.QueryRow(ctx, `SELECT doc::text FROM nxbaas_docs WHERE key=$1`, key).Scan(&b)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

func (d *DB) put(key string, b []byte, overwrite bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q := `INSERT INTO nxbaas_docs(key,doc) VALUES($1,$2::jsonb) ON CONFLICT (key) DO NOTHING`
	if overwrite {
		q = `INSERT INTO nxbaas_docs(key,doc) VALUES($1,$2::jsonb) ON CONFLICT (key) DO UPDATE SET doc=EXCLUDED.doc, updated_at=now()`
	}
	_, err := d.pool.Exec(ctx, q, key, string(b))
	return err
}

// Key names the document for a legacy file path.
func Key(path string) string { return filepath.Base(path) }

// Read returns the stored document for the file at path. In DB mode a missing row is
// filled from the legacy file (idempotent, the file stays). ok is false when neither
// exists. A database error is fatal in DB mode: starting empty would overwrite state.
func Read(path string) (b []byte, ok bool) {
	if Default == nil {
		b, err := os.ReadFile(path)
		return b, err == nil
	}
	key := Key(path)
	b, ok, err := Default.get(key)
	if err != nil {
		log.Fatalf("[nx-baas] postgres read %s: %v", key, err)
	}
	if ok {
		return b, true
	}
	fb, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if err := Default.put(key, fb, false); err != nil {
		log.Fatalf("[nx-baas] postgres import %s: %v", key, err)
	}
	b, ok, err = Default.get(key)
	if err != nil || !ok {
		log.Fatalf("[nx-baas] postgres import %s: not readable back: %v", key, err)
	}
	log.Printf("[nx-baas] imported %s into postgres (%d bytes; file kept)", key, len(fb))
	return b, true
}

// Write stores the document: a transactional upsert in DB mode, the old atomic file
// write otherwise.
func Write(path string, b []byte) error {
	if Default == nil {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	return Default.put(Key(path), b, true)
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `pg_host=localhost
pg_port=5433
pg_user=config_service
pg_password=secret
pg_database=config_service
invite_code=invite
jwt_secret=jwt-secret-with-enough-bytes
config_master_key=0123456789abcdef0123456789abcdef
public_listen_addr=0.0.0.0:9090
internal_listen_addr=127.0.0.1:9091
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.PGPort != 5433 {
		t.Fatalf("unexpected port %d", cfg.PGPort)
	}
	if cfg.PublicListenAddr != "0.0.0.0:9090" {
		t.Fatalf("unexpected public addr %s", cfg.PublicListenAddr)
	}
	if len(cfg.MasterKey) != 32 {
		t.Fatalf("unexpected master key length %d", len(cfg.MasterKey))
	}
}

func TestLoadRequiresInviteCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `pg_host=localhost
pg_user=config_service
pg_password=secret
pg_database=config_service
jwt_secret=jwt-secret-with-enough-bytes
config_master_key=0123456789abcdef0123456789abcdef
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected missing invite_code to fail")
	}
}

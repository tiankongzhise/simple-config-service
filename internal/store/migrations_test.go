package store

import (
	"strings"
	"testing"
)

func TestSchemaIncludesRSAProjectAndConfigColumns(t *testing.T) {
	required := []string{
		"rsa_private_key_ciphertext",
		"rsa_public_key_pem",
		"CREATE TABLE IF NOT EXISTS projects",
		"rsa_public_key_fingerprint",
		"project_id UUID REFERENCES projects(id)",
		"configs_unique_live_project_key",
		"configs_project_lookup_idx",
	}
	for _, fragment := range required {
		if !strings.Contains(schemaSQL, fragment) {
			t.Fatalf("schema is missing %q", fragment)
		}
	}
}

package app

import (
	"testing"
	"time"
)

func TestIssueAndVerifyToken(t *testing.T) {
	secret := []byte("jwt-secret-with-enough-bytes")
	now := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)

	token, issued, err := issueToken(secret, time.Hour, "user-id", "alice", now)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	claims, err := verifyToken(secret, token, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.Subject != issued.Subject || claims.Username != "alice" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestExpiredTokenFails(t *testing.T) {
	secret := []byte("jwt-secret-with-enough-bytes")
	now := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)

	token, _, err := issueToken(secret, time.Hour, "user-id", "alice", now)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := verifyToken(secret, token, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

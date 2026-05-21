package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Claims struct {
	Subject  string `json:"sub"`
	Username string `json:"username"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

func issueToken(secret []byte, ttl time.Duration, userID, username string, now time.Time) (string, Claims, error) {
	claims := Claims{
		Subject:  userID,
		Username: username,
		IssuedAt: now.Unix(),
		Expires:  now.Add(ttl).Unix(),
	}
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", Claims{}, err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, err
	}
	unsigned := b64url(headerJSON) + "." + b64url(claimsJSON)
	signature := signHS256(secret, unsigned)
	return unsigned + "." + b64url(signature), claims, nil
}

func verifyToken(secret []byte, token string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrUnauthorized
	}
	unsigned := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrUnauthorized
	}
	expected := signHS256(secret, unsigned)
	if !hmac.Equal(signature, expected) {
		return Claims{}, ErrUnauthorized
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrUnauthorized
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrUnauthorized
	}
	if claims.Subject == "" || claims.Expires == 0 {
		return Claims{}, ErrUnauthorized
	}
	if now.Unix() >= claims.Expires {
		return Claims{}, ErrUnauthorized
	}
	return claims, nil
}

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func signHS256(secret []byte, message string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(message))
	return mac.Sum(nil)
}

func bearerToken(header string) (string, error) {
	if header == "" {
		return "", ErrUnauthorized
	}
	typ, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(typ, "Bearer") || strings.TrimSpace(token) == "" {
		return "", ErrUnauthorized
	}
	return strings.TrimSpace(token), nil
}

func parsePositiveInt(value string, fallback int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%w: invalid integer", ErrBadRequest)
	}
	return parsed, nil
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrBadRequest),
		errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrForbidden),
		errors.Is(err, ErrNotFound),
		errors.Is(err, ErrConflict):
		return err
	default:
		return err
	}
}

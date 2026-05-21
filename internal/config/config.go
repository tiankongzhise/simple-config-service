package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"simple-config-service/pkg/configcrypto"
)

type Config struct {
	PGHost     string
	PGPort     int
	PGUser     string
	PGPassword string
	PGDatabase string
	PGSSLMode  string

	InviteCode string
	JWTSecret  []byte
	JWTTTL     time.Duration

	MasterKey []byte
	KeyID     string

	PublicListenAddr   string
	InternalListenAddr string
}

func Load(path string) (Config, error) {
	values := map[string]string{}
	if path != "" {
		fileValues, err := readDotEnv(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Config{}, err
		}
		for k, v := range fileValues {
			values[strings.ToLower(k)] = v
		}
	}

	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[strings.ToLower(key)] = value
		}
	}

	pgPort, err := parseInt(values, "pg_port", 5432)
	if err != nil {
		return Config{}, err
	}
	jwtTTL, err := parseDuration(values, "jwt_ttl", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	requiredKeys := []string{
		"pg_host",
		"pg_user",
		"pg_password",
		"pg_database",
		"invite_code",
		"jwt_secret",
		"config_master_key",
	}
	var missing []string
	for _, key := range requiredKeys {
		if required(values, key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}

	masterKey, err := configcrypto.ParseMasterKey(required(values, "config_master_key"))
	if err != nil {
		return Config{}, fmt.Errorf("config_master_key: %w", err)
	}

	cfg := Config{
		PGHost:             required(values, "pg_host"),
		PGPort:             pgPort,
		PGUser:             required(values, "pg_user"),
		PGPassword:         required(values, "pg_password"),
		PGDatabase:         required(values, "pg_database"),
		PGSSLMode:          get(values, "pg_sslmode", "disable"),
		InviteCode:         required(values, "invite_code"),
		JWTSecret:          []byte(required(values, "jwt_secret")),
		JWTTTL:             jwtTTL,
		MasterKey:          masterKey,
		KeyID:              get(values, "config_key_id", "default"),
		PublicListenAddr:   get(values, "public_listen_addr", "0.0.0.0:8080"),
		InternalListenAddr: get(values, "internal_listen_addr", "127.0.0.1:8081"),
	}

	if len(cfg.JWTSecret) < 16 {
		return Config{}, errors.New("jwt_secret must be at least 16 bytes")
	}
	if cfg.InviteCode == "" {
		return Config{}, errors.New("invite_code is required")
	}
	return cfg, nil
}

func (c Config) PostgresURL() string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.PGUser, c.PGPassword),
		Host:   net.JoinHostPort(c.PGHost, strconv.Itoa(c.PGPort)),
		Path:   c.PGDatabase,
	}
	q := u.Query()
	q.Set("sslmode", c.PGSSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

func readDotEnv(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func required(values map[string]string, key string) string {
	return strings.TrimSpace(values[strings.ToLower(key)])
}

func get(values map[string]string, key string, fallback string) string {
	if value := required(values, key); value != "" {
		return value
	}
	return fallback
}

func parseInt(values map[string]string, key string, fallback int) (int, error) {
	value := required(values, key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return parsed, nil
}

func parseDuration(values map[string]string, key string, fallback time.Duration) (time.Duration, error) {
	value := required(values, key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration like 24h: %w", key, err)
	}
	return parsed, nil
}

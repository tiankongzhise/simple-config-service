package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"simple-config-service/pkg/configcrypto"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrForbidden = errors.New("forbidden")
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (username, password_hash)
		VALUES ($1, $2)
		RETURNING id::text, username, password_hash, status, created_at, updated_at
	`, username, passwordHash)

	var user User
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Status, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	return user, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, username, password_hash, status, created_at, updated_at
		FROM users
		WHERE username = $1
	`, username)
	return scanUser(row)
}

func (s *Store) GetUserByID(ctx context.Context, userID string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, username, password_hash, status, created_at, updated_at
		FROM users
		WHERE id = $1
	`, userID)
	return scanUser(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var user User
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Status, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	return user, nil
}

type ConfigStatus string

const (
	ConfigEnabled  ConfigStatus = "enabled"
	ConfigDisabled ConfigStatus = "disabled"
)

type Config struct {
	ID               string               `json:"id"`
	UserID           string               `json:"user_id"`
	Key              string               `json:"key"`
	Application      string               `json:"application"`
	Environment      string               `json:"environment"`
	Description      string               `json:"description"`
	ValueCiphertext  string               `json:"value_ciphertext"`
	EncryptedDataKey string               `json:"encrypted_data_key"`
	Nonce            string               `json:"nonce"`
	DataKeyNonce     string               `json:"data_key_nonce"`
	Algorithm        string               `json:"algorithm"`
	KeyID            string               `json:"key_id"`
	Version          int                  `json:"version"`
	Status           ConfigStatus         `json:"status"`
	DeletedAt        *time.Time           `json:"deleted_at,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
	CryptoPayload    configcrypto.Payload `json:"-"`
}

type CreateConfigParams struct {
	UserID      string
	Key         string
	Application string
	Environment string
	Description string
	Status      ConfigStatus
	Payload     configcrypto.Payload
}

type UpdateConfigParams struct {
	UserID      string
	ConfigID    string
	Key         string
	Application string
	Environment string
	Description string
	Status      ConfigStatus
	Payload     configcrypto.Payload
}

type ListConfigsParams struct {
	UserID      string
	Application string
	Environment string
	Limit       int
	Offset      int
}

func (s *Store) CreateConfig(ctx context.Context, params CreateConfigParams) (Config, error) {
	if params.Status == "" {
		params.Status = ConfigEnabled
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Config{}, err
	}
	defer rollback(ctx, tx)

	row := tx.QueryRowContext(ctx, `
		INSERT INTO configs (
			user_id, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, status
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
	`, params.UserID, params.Key, params.Application, params.Environment, params.Description,
		params.Payload.ValueCiphertext, params.Payload.EncryptedDataKey, params.Payload.Nonce, params.Payload.DataKeyNonce,
		params.Payload.Algorithm, params.Payload.KeyID, string(params.Status))

	config, err := scanConfig(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Config{}, ErrConflict
		}
		return Config{}, err
	}
	if err := insertVersion(ctx, tx, config); err != nil {
		return Config{}, err
	}
	if err := tx.Commit(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (s *Store) UpdateConfig(ctx context.Context, params UpdateConfigParams) (Config, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Config{}, err
	}
	defer rollback(ctx, tx)

	row := tx.QueryRowContext(ctx, `
		UPDATE configs
		SET key = $3,
			application = $4,
			environment = $5,
			description = $6,
			value_ciphertext = $7,
			encrypted_data_key = $8,
			nonce = $9,
			data_key_nonce = $10,
			algorithm = $11,
			key_id = $12,
			status = $13,
			version = version + 1,
			updated_at = now()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
		RETURNING id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
	`, params.ConfigID, params.UserID, params.Key, params.Application, params.Environment, params.Description,
		params.Payload.ValueCiphertext, params.Payload.EncryptedDataKey, params.Payload.Nonce, params.Payload.DataKeyNonce,
		params.Payload.Algorithm, params.Payload.KeyID, string(params.Status))

	config, err := scanConfig(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Config{}, ErrConflict
		}
		return Config{}, err
	}
	if err := insertVersion(ctx, tx, config); err != nil {
		return Config{}, err
	}
	if err := tx.Commit(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (s *Store) DeleteConfig(ctx context.Context, userID, configID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE configs
		SET deleted_at = now(), status = $3, updated_at = now()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
	`, configID, userID, string(ConfigDisabled))
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListConfigs(ctx context.Context, params ListConfigsParams) ([]Config, error) {
	if params.Limit <= 0 || params.Limit > 100 {
		params.Limit = 50
	}
	if params.Offset < 0 {
		params.Offset = 0
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
		FROM configs
		WHERE user_id = $1
			AND deleted_at IS NULL
			AND ($2 = '' OR application = $2)
			AND ($3 = '' OR environment = $3)
		ORDER BY application, environment, key
		LIMIT $4 OFFSET $5
	`, params.UserID, params.Application, params.Environment, params.Limit, params.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanConfigs(rows)
}

func (s *Store) ListActiveConfigs(ctx context.Context, userID, application, environment string) ([]Config, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
		FROM configs
		WHERE user_id = $1
			AND application = $2
			AND environment = $3
			AND status = $4
			AND deleted_at IS NULL
		ORDER BY key
	`, userID, application, environment, string(ConfigEnabled))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanConfigs(rows)
}

func (s *Store) ListConfigVersions(ctx context.Context, userID, configID string) ([]Config, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT config_id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, NULL::timestamptz AS deleted_at,
			created_at, created_at AS updated_at
		FROM config_versions
		WHERE user_id = $1 AND config_id = $2
		ORDER BY version DESC
	`, userID, configID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanConfigs(rows)
}

func (s *Store) RollbackConfig(ctx context.Context, userID, configID string, version int) (Config, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Config{}, err
	}
	defer rollback(ctx, tx)

	var historical Config
	row := tx.QueryRowContext(ctx, `
		SELECT config_id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, NULL::timestamptz AS deleted_at,
			created_at, created_at AS updated_at
		FROM config_versions
		WHERE user_id = $1 AND config_id = $2 AND version = $3
	`, userID, configID, version)
	historical, err = scanConfig(row)
	if err != nil {
		return Config{}, err
	}

	row = tx.QueryRowContext(ctx, `
		UPDATE configs
		SET key = $3,
			application = $4,
			environment = $5,
			description = $6,
			value_ciphertext = $7,
			encrypted_data_key = $8,
			nonce = $9,
			data_key_nonce = $10,
			algorithm = $11,
			key_id = $12,
			status = $13,
			version = version + 1,
			updated_at = now()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
		RETURNING id::text, user_id::text, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
	`, configID, userID, historical.Key, historical.Application, historical.Environment, historical.Description,
		historical.ValueCiphertext, historical.EncryptedDataKey, historical.Nonce, historical.DataKeyNonce,
		historical.Algorithm, historical.KeyID, string(historical.Status))
	config, err := scanConfig(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Config{}, ErrConflict
		}
		return Config{}, err
	}
	if err := insertVersion(ctx, tx, config); err != nil {
		return Config{}, err
	}
	if err := tx.Commit(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (s *Store) Audit(ctx context.Context, userID, action, resourceType, resourceID string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (user_id, action, resource_type, resource_id, metadata)
		VALUES (NULLIF($1, '')::uuid, $2, $3, NULLIF($4, '')::uuid, $5)
	`, userID, action, resourceType, resourceID, body)
	return err
}

func scanConfig(row scanner) (Config, error) {
	var config Config
	if err := row.Scan(
		&config.ID,
		&config.UserID,
		&config.Key,
		&config.Application,
		&config.Environment,
		&config.Description,
		&config.ValueCiphertext,
		&config.EncryptedDataKey,
		&config.Nonce,
		&config.DataKeyNonce,
		&config.Algorithm,
		&config.KeyID,
		&config.Version,
		&config.Status,
		&config.DeletedAt,
		&config.CreatedAt,
		&config.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Config{}, ErrNotFound
		}
		return Config{}, err
	}
	config.CryptoPayload = configcrypto.Payload{
		ValueCiphertext:  config.ValueCiphertext,
		EncryptedDataKey: config.EncryptedDataKey,
		Nonce:            config.Nonce,
		DataKeyNonce:     config.DataKeyNonce,
		Algorithm:        config.Algorithm,
		KeyID:            config.KeyID,
	}
	return config, nil
}

func scanConfigs(rows *sql.Rows) ([]Config, error) {
	configs := []Config{}
	for rows.Next() {
		config, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return configs, nil
}

func insertVersion(ctx context.Context, tx *sql.Tx, config Config) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO config_versions (
			config_id, user_id, version, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, status
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, config.ID, config.UserID, config.Version, config.Key, config.Application, config.Environment, config.Description,
		config.ValueCiphertext, config.EncryptedDataKey, config.Nonce, config.DataKeyNonce,
		config.Algorithm, config.KeyID, string(config.Status))
	return err
}

func rollback(_ context.Context, tx *sql.Tx) {
	_ = tx.Rollback()
}

func isUniqueViolation(err error) bool {
	var pgErr *pq.Error
	if errors.As(err, &pgErr) {
		return string(pgErr.Code) == "23505"
	}
	return false
}

func WrapNotFound(name string, err error) error {
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	return err
}

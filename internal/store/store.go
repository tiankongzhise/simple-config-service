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
	ID                            string               `json:"id"`
	Username                      string               `json:"username"`
	PasswordHash                  string               `json:"-"`
	RSAPrivateKeyCiphertext       string               `json:"-"`
	RSAPrivateKeyEncryptedDataKey string               `json:"-"`
	RSAPrivateKeyNonce            string               `json:"-"`
	RSAPrivateKeyAlgorithm        string               `json:"-"`
	RSAPrivateKeyKeyID            string               `json:"-"`
	RSAPublicKeyPEM               string               `json:"rsa_public_key"`
	RSAPublicKeyFingerprint       string               `json:"rsa_public_key_fingerprint"`
	Status                        string               `json:"status"`
	CreatedAt                     time.Time            `json:"created_at"`
	UpdatedAt                     time.Time            `json:"updated_at"`
	RSAPrivateKeyPayload          configcrypto.Payload `json:"-"`
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (User, error) {
	return s.CreateUserWithKeys(ctx, CreateUserParams{
		Username:     username,
		PasswordHash: passwordHash,
	})
}

type CreateUserParams struct {
	Username             string
	PasswordHash         string
	PrivateKeyPayload    configcrypto.Payload
	PublicKeyPEM         string
	PublicKeyFingerprint string
}

func (s *Store) CreateUserWithKeys(ctx context.Context, params CreateUserParams) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (
			username, password_hash,
			rsa_private_key_ciphertext, rsa_private_key_encrypted_data_key,
			rsa_private_key_nonce, rsa_private_key_algorithm, rsa_private_key_key_id,
			rsa_public_key_pem, rsa_public_key_fingerprint
		)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''))
		RETURNING id::text, username, password_hash,
			COALESCE(rsa_private_key_ciphertext, ''),
			COALESCE(rsa_private_key_encrypted_data_key, ''),
			COALESCE(rsa_private_key_nonce, ''),
			COALESCE(rsa_private_key_algorithm, ''),
			COALESCE(rsa_private_key_key_id, ''),
			COALESCE(rsa_public_key_pem, ''),
			COALESCE(rsa_public_key_fingerprint, ''),
			status, created_at, updated_at
	`, params.Username, params.PasswordHash,
		params.PrivateKeyPayload.ValueCiphertext, params.PrivateKeyPayload.EncryptedDataKey,
		params.PrivateKeyPayload.Nonce, params.PrivateKeyPayload.Algorithm, params.PrivateKeyPayload.KeyID,
		params.PublicKeyPEM, params.PublicKeyFingerprint)

	user, err := scanUser(row)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	return user, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, username, password_hash,
			COALESCE(rsa_private_key_ciphertext, ''),
			COALESCE(rsa_private_key_encrypted_data_key, ''),
			COALESCE(rsa_private_key_nonce, ''),
			COALESCE(rsa_private_key_algorithm, ''),
			COALESCE(rsa_private_key_key_id, ''),
			COALESCE(rsa_public_key_pem, ''),
			COALESCE(rsa_public_key_fingerprint, ''),
			status, created_at, updated_at
		FROM users
		WHERE username = $1
	`, username)
	return scanUser(row)
}

func (s *Store) GetUserByID(ctx context.Context, userID string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, username, password_hash,
			COALESCE(rsa_private_key_ciphertext, ''),
			COALESCE(rsa_private_key_encrypted_data_key, ''),
			COALESCE(rsa_private_key_nonce, ''),
			COALESCE(rsa_private_key_algorithm, ''),
			COALESCE(rsa_private_key_key_id, ''),
			COALESCE(rsa_public_key_pem, ''),
			COALESCE(rsa_public_key_fingerprint, ''),
			status, created_at, updated_at
		FROM users
		WHERE id = $1
	`, userID)
	return scanUser(row)
}

func (s *Store) UpdateUserRSAKey(ctx context.Context, userID string, payload configcrypto.Payload, publicKeyPEM, fingerprint string) (User, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE users
		SET rsa_private_key_ciphertext = $2,
			rsa_private_key_encrypted_data_key = $3,
			rsa_private_key_nonce = $4,
			rsa_private_key_algorithm = $5,
			rsa_private_key_key_id = $6,
			rsa_public_key_pem = $7,
			rsa_public_key_fingerprint = $8,
			updated_at = now()
		WHERE id = $1
		RETURNING id::text, username, password_hash,
			COALESCE(rsa_private_key_ciphertext, ''),
			COALESCE(rsa_private_key_encrypted_data_key, ''),
			COALESCE(rsa_private_key_nonce, ''),
			COALESCE(rsa_private_key_algorithm, ''),
			COALESCE(rsa_private_key_key_id, ''),
			COALESCE(rsa_public_key_pem, ''),
			COALESCE(rsa_public_key_fingerprint, ''),
			status, created_at, updated_at
	`, userID, payload.ValueCiphertext, payload.EncryptedDataKey, payload.Nonce, payload.Algorithm, payload.KeyID, publicKeyPEM, fingerprint)
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	return user, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var user User
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.RSAPrivateKeyCiphertext,
		&user.RSAPrivateKeyEncryptedDataKey,
		&user.RSAPrivateKeyNonce,
		&user.RSAPrivateKeyAlgorithm,
		&user.RSAPrivateKeyKeyID,
		&user.RSAPublicKeyPEM,
		&user.RSAPublicKeyFingerprint,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	user.RSAPrivateKeyPayload = configcrypto.Payload{
		ValueCiphertext:  user.RSAPrivateKeyCiphertext,
		EncryptedDataKey: user.RSAPrivateKeyEncryptedDataKey,
		Nonce:            user.RSAPrivateKeyNonce,
		Algorithm:        user.RSAPrivateKeyAlgorithm,
		KeyID:            user.RSAPrivateKeyKeyID,
	}
	return user, nil
}

type Project struct {
	ID                      string    `json:"id"`
	UserID                  string    `json:"user_id"`
	Name                    string    `json:"name"`
	Description             string    `json:"description"`
	RSAPublicKeyPEM         string    `json:"rsa_public_key"`
	RSAPublicKeyFingerprint string    `json:"rsa_public_key_fingerprint"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

type CreateProjectParams struct {
	UserID                  string
	Name                    string
	Description             string
	RSAPublicKeyPEM         string
	RSAPublicKeyFingerprint string
}

func (s *Store) CreateProject(ctx context.Context, params CreateProjectParams) (Project, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO projects (user_id, name, description, rsa_public_key_pem, rsa_public_key_fingerprint)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text, user_id::text, name, description, rsa_public_key_pem, rsa_public_key_fingerprint, created_at, updated_at
	`, params.UserID, params.Name, params.Description, params.RSAPublicKeyPEM, params.RSAPublicKeyFingerprint)
	project, err := scanProject(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Project{}, ErrConflict
		}
		return Project{}, err
	}
	return project, nil
}

func (s *Store) GetProjectByID(ctx context.Context, userID, projectID string) (Project, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id::text, user_id::text, name, description, rsa_public_key_pem, rsa_public_key_fingerprint, created_at, updated_at
		FROM projects
		WHERE user_id = $1 AND id = $2
	`, userID, projectID)
	return scanProject(row)
}

func (s *Store) ListProjects(ctx context.Context, userID string) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, user_id::text, name, description, rsa_public_key_pem, rsa_public_key_fingerprint, created_at, updated_at
		FROM projects
		WHERE user_id = $1
		ORDER BY name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	projects := []Project{}
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return projects, nil
}

func (s *Store) UpdateProjectRSAKey(ctx context.Context, userID, projectID, publicKeyPEM, fingerprint string) (Project, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE projects
		SET rsa_public_key_pem = $3,
			rsa_public_key_fingerprint = $4,
			updated_at = now()
		WHERE user_id = $1 AND id = $2
		RETURNING id::text, user_id::text, name, description, rsa_public_key_pem, rsa_public_key_fingerprint, created_at, updated_at
	`, userID, projectID, publicKeyPEM, fingerprint)
	return scanProject(row)
}

func scanProject(row scanner) (Project, error) {
	var project Project
	if err := row.Scan(
		&project.ID,
		&project.UserID,
		&project.Name,
		&project.Description,
		&project.RSAPublicKeyPEM,
		&project.RSAPublicKeyFingerprint,
		&project.CreatedAt,
		&project.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Project{}, ErrNotFound
		}
		return Project{}, err
	}
	return project, nil
}

type ConfigStatus string

const (
	ConfigEnabled  ConfigStatus = "enabled"
	ConfigDisabled ConfigStatus = "disabled"
)

type Config struct {
	ID               string               `json:"id"`
	UserID           string               `json:"user_id"`
	ProjectID        string               `json:"project_id"`
	ProjectName      string               `json:"project_name"`
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
	ProjectID   string
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
	ProjectID   string
	Key         string
	Application string
	Environment string
	Description string
	Status      ConfigStatus
	Payload     configcrypto.Payload
}

type ListConfigsParams struct {
	UserID      string
	ProjectID   string
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
			user_id, project_id, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, status
		)
		VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11, $12, $13)
		RETURNING id::text, user_id::text, COALESCE(project_id::text, ''),
			COALESCE((SELECT name FROM projects WHERE projects.id = configs.project_id), ''),
			key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
	`, params.UserID, params.ProjectID, params.Key, params.Application, params.Environment, params.Description,
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
		SET project_id = NULLIF($3, '')::uuid,
			key = $4,
			application = $5,
			environment = $6,
			description = $7,
			value_ciphertext = $8,
			encrypted_data_key = $9,
			nonce = $10,
			data_key_nonce = NULLIF($11, ''),
			algorithm = $12,
			key_id = $13,
			status = $14,
			version = version + 1,
			updated_at = now()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
		RETURNING id::text, user_id::text, COALESCE(project_id::text, ''),
			COALESCE((SELECT name FROM projects WHERE projects.id = configs.project_id), ''),
			key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
	`, params.ConfigID, params.UserID, params.ProjectID, params.Key, params.Application, params.Environment, params.Description,
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
		SELECT configs.id::text, configs.user_id::text, COALESCE(configs.project_id::text, ''),
			COALESCE(projects.name, ''),
			configs.key, configs.application, configs.environment, configs.description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, deleted_at, configs.created_at, configs.updated_at
		FROM configs
		LEFT JOIN projects ON projects.id = configs.project_id
		WHERE configs.user_id = $1
			AND configs.deleted_at IS NULL
			AND ($2 = '' OR configs.project_id = NULLIF($2, '')::uuid)
			AND ($3 = '' OR configs.application = $3 OR projects.name = $3)
			AND ($4 = '' OR configs.environment = $4)
		ORDER BY COALESCE(projects.name, configs.application), configs.environment, configs.key
		LIMIT $5 OFFSET $6
	`, params.UserID, params.ProjectID, params.Application, params.Environment, params.Limit, params.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanConfigs(rows)
}

func (s *Store) ListActiveConfigs(ctx context.Context, userID, application, environment string) ([]Config, error) {
	return s.ListActiveProjectConfigs(ctx, userID, "", application, environment)
}

func (s *Store) ListActiveProjectConfigs(ctx context.Context, userID, projectID, application, environment string) ([]Config, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT configs.id::text, configs.user_id::text, COALESCE(configs.project_id::text, ''),
			COALESCE(projects.name, ''),
			configs.key, configs.application, configs.environment, configs.description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, deleted_at, configs.created_at, configs.updated_at
		FROM configs
		LEFT JOIN projects ON projects.id = configs.project_id
		WHERE configs.user_id = $1
			AND ($2 = '' OR configs.project_id = NULLIF($2, '')::uuid)
			AND ($3 = '' OR configs.application = $3 OR projects.name = $3)
			AND configs.environment = $4
			AND configs.status = $5
			AND configs.deleted_at IS NULL
		ORDER BY configs.key
	`, userID, projectID, application, environment, string(ConfigEnabled))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanConfigs(rows)
}

func (s *Store) ListConfigVersions(ctx context.Context, userID, configID string) ([]Config, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT config_id::text, config_versions.user_id::text, COALESCE(config_versions.project_id::text, ''),
			COALESCE(projects.name, ''),
			config_versions.key, config_versions.application, config_versions.environment, config_versions.description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, NULL::timestamptz AS deleted_at,
			config_versions.created_at, config_versions.created_at AS updated_at
		FROM config_versions
		LEFT JOIN projects ON projects.id = config_versions.project_id
		WHERE config_versions.user_id = $1 AND config_id = $2
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
		SELECT config_id::text, config_versions.user_id::text, COALESCE(config_versions.project_id::text, ''),
			COALESCE(projects.name, ''),
			config_versions.key, config_versions.application, config_versions.environment, config_versions.description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, NULL::timestamptz AS deleted_at,
			config_versions.created_at, config_versions.created_at AS updated_at
		FROM config_versions
		LEFT JOIN projects ON projects.id = config_versions.project_id
		WHERE config_versions.user_id = $1 AND config_id = $2 AND version = $3
	`, userID, configID, version)
	historical, err = scanConfig(row)
	if err != nil {
		return Config{}, err
	}

	row = tx.QueryRowContext(ctx, `
		UPDATE configs
		SET project_id = NULLIF($3, '')::uuid,
			key = $4,
			application = $5,
			environment = $6,
			description = $7,
			value_ciphertext = $8,
			encrypted_data_key = $9,
			nonce = $10,
			data_key_nonce = NULLIF($11, ''),
			algorithm = $12,
			key_id = $13,
			status = $14,
			version = version + 1,
			updated_at = now()
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
		RETURNING id::text, user_id::text, COALESCE(project_id::text, ''),
			COALESCE((SELECT name FROM projects WHERE projects.id = configs.project_id), ''),
			key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, COALESCE(data_key_nonce, ''),
			algorithm, key_id, version, status, deleted_at, created_at, updated_at
	`, configID, userID, historical.ProjectID, historical.Key, historical.Application, historical.Environment, historical.Description,
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
		&config.ProjectID,
		&config.ProjectName,
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
			config_id, user_id, project_id, version, key, application, environment, description,
			value_ciphertext, encrypted_data_key, nonce, data_key_nonce,
			algorithm, key_id, status
		)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, ''), $13, $14, $15)
	`, config.ID, config.UserID, config.ProjectID, config.Version, config.Key, config.Application, config.Environment, config.Description,
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

package authstorepostgres

import (
	"context"
	"fmt"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// CreateUser создаёт пользователя (email ещё не подтверждён).
// user_id генерируется на стороне Go — случайный hex, как в memory-сторе.
func (s *Store) CreateUser(ctx context.Context, username, email string, passwordHash []byte) (authstore.User, error) {
	id := newID()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (user_id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		id, username, email, passwordHash,
	)
	if err != nil {
		return authstore.User{}, mapError(err)
	}
	return authstore.User{
		ID:           id,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
	}, nil
}

// CreateUserWithCode атомарно создаёт пользователя и его первый код
// подтверждения: обе вставки в одной транзакции, частичного результата
// (пользователь без кода) не бывает.
func (s *Store) CreateUserWithCode(ctx context.Context, username, email string, passwordHash []byte, codeHash string, codeExpiresAt time.Time) (authstore.User, error) {
	id := newID()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authstore.User{}, fmt.Errorf("authstorepostgres: begin create user: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`INSERT INTO users (user_id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		id, username, email, passwordHash,
	); err != nil {
		return authstore.User{}, mapError(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		id, codeHash, codeExpiresAt,
	); err != nil {
		return authstore.User{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return authstore.User{}, fmt.Errorf("authstorepostgres: commit create user: %w", err)
	}
	return authstore.User{
		ID:           id,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
	}, nil
}

// GetUserByUsername ищет пользователя по имени.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (authstore.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE username = $1`, username))
}

// GetUserByEmail ищет пользователя по адресу email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (authstore.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

// GetUserByID ищет пользователя по user_id.
func (s *Store) GetUserByID(ctx context.Context, userID string) (authstore.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE user_id = $1`, userID))
}

// GetUserByConnectKey ищет пользователя по ключу подключения.
func (s *Store) GetUserByConnectKey(ctx context.Context, connectKey string) (authstore.User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE connect_key = $1`, connectKey))
}

// VerifyEmail помечает email подтверждённым (идемпотентно).
func (s *Store) VerifyEmail(ctx context.Context, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET email_verified_at = now() WHERE user_id = $1`, userID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrUserNotFound
	}
	return nil
}

// SetConnectKey назначает пользователю ключ подключения.
func (s *Store) SetConnectKey(ctx context.Context, userID, connectKey string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET connect_key = $2 WHERE user_id = $1`, userID, connectKey)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrUserNotFound
	}
	return nil
}

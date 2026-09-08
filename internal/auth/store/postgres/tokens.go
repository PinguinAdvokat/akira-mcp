package authstorepostgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// SaveRefresh сохраняет запись о refresh-токене.
func (s *Store) SaveRefresh(ctx context.Context, tok authstore.RefreshToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		tok.TokenHash, tok.UserID, tok.ExpiresAt, tok.CreatedAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// RotateRefresh атомарно потребляет старый refresh-токен и сохраняет
// новый — одной транзакцией: DELETE … RETURNING забирает запись ровно
// у одного конкурентного вызова, а вставка нового токена в той же
// транзакции означает, что сбой вставки откатывает и потребление
// (старый токен остаётся действующим). Истёкший токен не потребляется.
// user_id нового токена наследуется от старого. Возвращает потреблённую
// запись.
func (s *Store) RotateRefresh(ctx context.Context, oldTokenHash string, newTok authstore.RefreshToken) (authstore.RefreshToken, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return authstore.RefreshToken{}, fmt.Errorf("authstorepostgres: begin rotate refresh: %w", err)
	}
	defer tx.Rollback(ctx)

	var old authstore.RefreshToken
	err = tx.QueryRow(ctx,
		`DELETE FROM refresh_tokens WHERE token_hash = $1 AND expires_at > now()
		 RETURNING token_hash, user_id, expires_at, created_at`, oldTokenHash,
	).Scan(&old.TokenHash, &old.UserID, &old.ExpiresAt, &old.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return authstore.RefreshToken{}, authstore.ErrRefreshNotFound
	}
	if err != nil {
		return authstore.RefreshToken{}, err
	}

	newTok.UserID = old.UserID
	if _, err := tx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		newTok.TokenHash, newTok.UserID, newTok.ExpiresAt, newTok.CreatedAt,
	); err != nil {
		return authstore.RefreshToken{}, mapError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return authstore.RefreshToken{}, fmt.Errorf("authstorepostgres: commit rotate refresh: %w", err)
	}
	return old, nil
}

// RevokeRefresh удаляет запись; идемпотентна.
func (s *Store) RevokeRefresh(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// SaveEmailVerification сохраняет код подтверждения, замещая предыдущий
// активный код пользователя (user_id — PK таблицы: INSERT … ON CONFLICT
// перезаписывает и сбрасывает счётчик попыток).
func (s *Store) SaveEmailVerification(ctx context.Context, tok authstore.EmailVerification) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO email_verifications (token_hash, user_id, expires_at, created_at, attempts)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (user_id) DO UPDATE SET
		   token_hash = EXCLUDED.token_hash,
		   expires_at = EXCLUDED.expires_at,
		   created_at = EXCLUDED.created_at,
		   attempts = 0`,
		tok.CodeHash, tok.UserID, tok.ExpiresAt, tok.CreatedAt, tok.Attempts)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// CompleteEmailVerification атомарно сверяет и потребляет код,
// помечает email подтверждённым и назначает connect_key — всё в одной
// транзакции; строка кода берётся под FOR UPDATE, так что конкурентные
// вводы одного кода сериализуются. Конфликт connect_key проверяется до
// потребления кода: повтор с другим ключом не сжигает код.
func (s *Store) CompleteEmailVerification(ctx context.Context, userID, codeHash, connectKey string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("authstorepostgres: begin complete verification: %w", err)
	}
	defer tx.Rollback(ctx)

	var tok authstore.EmailVerification
	err = tx.QueryRow(ctx,
		`SELECT token_hash, expires_at, created_at, attempts FROM email_verifications
		 WHERE user_id = $1 FOR UPDATE`, userID,
	).Scan(&tok.CodeHash, &tok.ExpiresAt, &tok.CreatedAt, &tok.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return authstore.ErrVerificationNotFound
	}
	if err != nil {
		return err
	}

	if !time.Now().Before(tok.ExpiresAt) {
		// Истёкший код удаляем — заменит только resend.
		if _, err := tx.Exec(ctx, `DELETE FROM email_verifications WHERE user_id = $1`, userID); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("authstorepostgres: commit complete verification: %w", err)
		}
		return authstore.ErrVerificationNotFound
	}
	if tok.Attempts >= authstore.MaxVerificationAttempts {
		return authstore.ErrVerificationNotFound // запись остаётся: resend замещает её
	}
	if tok.CodeHash != codeHash {
		if _, err := tx.Exec(ctx,
			`UPDATE email_verifications SET attempts = attempts + 1 WHERE user_id = $1`, userID,
		); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("authstorepostgres: commit complete verification: %w", err)
		}
		return authstore.ErrVerificationWrongCode
	}

	// Хеш совпал. Сначала убеждаемся, что connect_key свободен —
	// до потребления кода; конкурентное назначение того же ключа
	// другому пользователю поймает unique-ограничение users.connect_key,
	// транзакция откатится и код тоже останется цел.
	var clash bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE connect_key = $2 AND user_id <> $1)`,
		userID, connectKey).Scan(&clash); err != nil {
		return err
	}
	if clash {
		return authstore.ErrConnectKeyExists
	}

	tag, err := tx.Exec(ctx,
		`UPDATE users SET email_verified_at = now(), connect_key = $2 WHERE user_id = $1`,
		userID, connectKey)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrUserNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM email_verifications WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("authstorepostgres: commit complete verification: %w", err)
	}
	return nil
}

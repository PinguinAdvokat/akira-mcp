// Пакет authstorepostgres — реализация authstore.Store поверх Postgres
// (pgxpool). Схема создаётся встроенными миграциями при подключении;
// их применение сериализуется advisory-локом, поэтому параллельный
// старт auth-сервиса и akira-server (или нескольких реплик) безопасен.
// Хранилище общее для auth-сервиса и akira-server: сервер ищет
// пользователя по connect_key при подключении akira-client.
package authstorepostgres

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// newID возвращает случайный hex-идентификатор пользователя
// (по образцу connection.NewID).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	return hex.EncodeToString(b[:])
}

const (
	// connectTimeout — таймаут установления одного соединения к БД:
	// зависший адрес (милки-коннект Docker/NAT) не должен держать
	// процесс в молчании.
	connectTimeout = 5 * time.Second
	// startupTimeout — общий бюджет на подключение и миграции. Хост
	// может резолвиться в несколько адресов (localhost — и ::1, и
	// 127.0.0.1), и каждый адрес тратит свой connectTimeout, поэтому
	// весь старт обязан иметь собственный потолок — иначе недоступная
	// БД растягивает запуск на десятки секунд.
	startupTimeout = 10 * time.Second
)

// migrationsLockKey — ключ pg_advisory_xact_lock, сериализующий запуск
// миграций между процессами. Значение произвольное, но фиксированное;
// важно только, чтобы оно не пересекалось с другими advisory-ключами БД.
const migrationsLockKey int64 = 0x616B697261 // "akira"

// migrations — SQL-миграции, применяемые при подключении. Имена вида
// NNNN_description.sql: NNNN — номер версии, применяются по возрастанию.
//
//go:embed migrations/*.sql
var migrations embed.FS

// Store — Postgres-хранилище. Пул соединений один на процесс;
// конкурентный доступ безопасен (pgxpool).
type Store struct {
	pool *pgxpool.Pool
}

// New подключается к БД по database URL (postgres://…), применяет
// миграции и возвращает хранилище. На весь старт (подключение +
// миграции) даётся общий таймаут startupTimeout: недоступная БД —
// быстрая ошибка, а не вечное молчание.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("authstorepostgres: parse database url: %w", err)
	}
	cfg.ConnConfig.ConnectTimeout = connectTimeout

	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("authstorepostgres: connect: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	purgeExpired(ctx, pool)
	return &Store{pool: pool}, nil
}

// Close закрывает пул соединений.
func (s *Store) Close() {
	s.pool.Close()
}

// migrate применяет неприменённые миграции из migrations. Учёт — в
// таблице schema_migrations. Всё применение идёт в одной транзакции
// под pg_advisory_xact_lock: при параллельном старте нескольких
// процессов (auth + akira-server) миграции применяет ровно один,
// остальные дожидаются лока и видят уже применённую схему —
// check-then-apply без лока гонится между стартерами.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("authstorepostgres: begin migrations: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationsLockKey); err != nil {
		return fmt.Errorf("authstorepostgres: lock migrations: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version int PRIMARY KEY
		)`); err != nil {
		return fmt.Errorf("authstorepostgres: create schema_migrations: %w", err)
	}

	entries, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("authstorepostgres: glob migrations: %w", err)
	}
	sort.Strings(entries)

	for _, name := range entries {
		version, err := strconv.Atoi(strings.SplitN(strings.TrimPrefix(strings.TrimSuffix(name, ".sql"), "migrations/"), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("authstorepostgres: bad migration name %q: %w", name, err)
		}

		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return fmt.Errorf("authstorepostgres: check migration %d: %w", version, err)
		}
		if applied {
			continue
		}

		body, err := migrations.ReadFile(name)
		if err != nil {
			return fmt.Errorf("authstorepostgres: read migration %q: %w", name, err)
		}

		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("authstorepostgres: apply migration %d: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			return fmt.Errorf("authstorepostgres: record migration %d: %w", version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("authstorepostgres: commit migrations: %w", err)
	}
	return nil
}

// purgeExpired удаляет протухшие refresh-токены и коды подтверждения:
// потреблены они уже не будут, а копить их незачем. Вызывается один раз
// при старте, чтобы не добавлять нагрузку на каждый запрос; очистка
// best-effort — при неудаче строки просто дождутся следующего старта.
func purgeExpired(ctx context.Context, pool *pgxpool.Pool) {
	_, _ = pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < now()`)
	_, _ = pool.Exec(ctx, `DELETE FROM email_verifications WHERE expires_at < now()`)
}

// mapError переводит ошибки Postgres в сентинелы authstore.
func mapError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		switch pgErr.ConstraintName {
		case "users_username_key":
			return authstore.ErrUserExists
		case "users_email_key":
			return authstore.ErrEmailExists
		case "users_connect_key_key":
			return authstore.ErrConnectKeyExists
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authstore.ErrUserNotFound
	}
	return err
}

const userCols = `user_id, username, email, password_hash, connect_key, email_verified_at`

// scanUser собирает User из строки запроса (в порядке userCols).
func scanUser(row pgx.Row) (authstore.User, error) {
	var u authstore.User
	var verifiedAt *time.Time
	var connectKey *string // NULL, пока email не подтверждён
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &connectKey, &verifiedAt); err != nil {
		return authstore.User{}, mapError(err)
	}
	if connectKey != nil {
		u.ConnectKey = *connectKey
	}
	u.EmailVerified = verifiedAt != nil
	return u, nil
}

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

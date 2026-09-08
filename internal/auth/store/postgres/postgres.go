// Пакет authstorepostgres — реализация authstore.Store поверх Postgres
// (pgxpool). Схема создаётся встроенными миграциями при подключении
// (migrations.go); их применение сериализуется advisory-локом, поэтому
// параллельный старт auth-сервиса и akira-server (или нескольких реплик)
// безопасен. Хранилище общее для auth-сервиса и akira-server: сервер ищет
// пользователя по connect_key при подключении akira-client.
//
// Файлы пакета: postgres.go — подключение и общие хелперы;
// migrations.go — миграции схемы и очистка протухших записей;
// users.go — операции над пользователями; tokens.go — refresh-токены
// и коды подтверждения email.
package authstorepostgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

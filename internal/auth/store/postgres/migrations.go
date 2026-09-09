package authstorepostgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
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

// purgeExpired удаляет протухшие refresh-токены, коды подтверждения
// и коды авторизации: потреблены они уже не будут, а копить их незачем.
// Вызывается один раз при старте, чтобы не добавлять нагрузку на каждый
// запрос; очистка best-effort — при неудаче строки просто дождутся
// следующего старта.
func purgeExpired(ctx context.Context, pool *pgxpool.Pool) {
	_, _ = pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < now()`)
	_, _ = pool.Exec(ctx, `DELETE FROM email_verifications WHERE expires_at < now()`)
	_, _ = pool.Exec(ctx, `DELETE FROM oauth_codes WHERE expires_at < now()`)
}

// Пакет authstore — обобщённый интерфейс хранилища auth-сервиса:
// пользователи и refresh-токены. Сейчас существует только in-memory
// реализация (internal/auth/store/memory); интерфейс рассчитан на
// будущую реализацию поверх Postgres.
package authstore

import (
	"context"
	"errors"
	"time"
)

// Ошибки хранилища. Сравниваются через errors.Is.
var (
	ErrUserNotFound    = errors.New("authstore: user not found")
	ErrUserExists      = errors.New("authstore: user already exists")
	ErrRefreshNotFound = errors.New("authstore: refresh token not found")
)

// User — учётная запись. PasswordHash — bcrypt-хеш; plaintext-пароль
// хранилище не видит никогда.
type User struct {
	ID           string
	Username     string
	PasswordHash []byte
}

// RefreshToken — запись об opaque refresh-токене. TokenHash — sha256
// от исходного токена: сам токен хранению не подлежит.
type RefreshToken struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// UserStore — работа с пользователями.
type UserStore interface {
	// CreateUser создаёт пользователя; при занятом имени — ErrUserExists.
	CreateUser(ctx context.Context, username string, passwordHash []byte) (User, error)
	// GetUserByUsername ищет пользователя по имени; если нет — ErrUserNotFound.
	GetUserByUsername(ctx context.Context, username string) (User, error)
}

// RefreshStore — работа с refresh-токенами.
type RefreshStore interface {
	// SaveRefresh сохраняет запись о токене.
	SaveRefresh(ctx context.Context, tok RefreshToken) error
	// ConsumeRefresh атомарно находит запись по хешу и удаляет её:
	// токен можно использовать ровно один раз (ротация = потребление).
	// Если записи нет — ErrRefreshNotFound.
	ConsumeRefresh(ctx context.Context, tokenHash string) (RefreshToken, error)
	// RevokeRefresh удаляет запись; идемпотентна (отсутствие записи — не ошибка).
	RevokeRefresh(ctx context.Context, tokenHash string) error
}

// Store — полное хранилище auth-сервиса: одна реализация закрывает
// оба интерфейса.
type Store interface {
	UserStore
	RefreshStore
}

// Пакет authstorememory — in-memory реализация authstore.Store
// без сохранения на диск: всё пропадает при рестарте процесса.
// Реализация для разработки и тестов; продакшн-цель — Postgres.
package authstorememory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

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

// Store — in-memory хранилище. Потокобезопасно: хендлеры HTTP
// обращаются к нему конкурентно, а ConsumeRefresh обязан быть
// атомарным (иначе одноразовость refresh-токена нарушится гонкой).
type Store struct {
	mu      sync.Mutex
	users   map[string]authstore.User         // username → User
	refresh map[string]authstore.RefreshToken // tokenHash → RefreshToken
}

// New создаёт пустое хранилище.
func New() *Store {
	return &Store{
		users:   make(map[string]authstore.User),
		refresh: make(map[string]authstore.RefreshToken),
	}
}

// CreateUser создаёт пользователя со случайным ID.
func (s *Store) CreateUser(_ context.Context, username string, passwordHash []byte) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[username]; ok {
		return authstore.User{}, authstore.ErrUserExists
	}
	u := authstore.User{
		ID:           newID(),
		Username:     username,
		PasswordHash: passwordHash,
	}
	s.users[username] = u
	return u, nil
}

// GetUserByUsername ищет пользователя по имени.
func (s *Store) GetUserByUsername(_ context.Context, username string) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return authstore.User{}, authstore.ErrUserNotFound
	}
	return u, nil
}

// SaveRefresh сохраняет запись о refresh-токене.
func (s *Store) SaveRefresh(_ context.Context, tok authstore.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refresh[tok.TokenHash] = tok
	return nil
}

// ConsumeRefresh атомарно (под общим локом) находит и удаляет запись:
// побеждает ровно один конкурентный вызов, остальные получают
// ErrRefreshNotFound.
func (s *Store) ConsumeRefresh(_ context.Context, tokenHash string) (authstore.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.refresh[tokenHash]
	if !ok {
		return authstore.RefreshToken{}, authstore.ErrRefreshNotFound
	}
	delete(s.refresh, tokenHash)
	return tok, nil
}

// RevokeRefresh удаляет запись; идемпотентна.
func (s *Store) RevokeRefresh(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refresh, tokenHash)
	return nil
}

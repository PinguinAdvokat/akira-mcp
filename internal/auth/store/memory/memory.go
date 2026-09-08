// Пакет authstorememory — in-memory реализация authstore.Store
// без сохранения на диск: всё пропадает при рестарте процесса.
// Реализация для разработки и тестов; продакшн-цель — Postgres.
package authstorememory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

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
// обращаются к нему конкурентно, а одноразовость токенов и кодов
// (RotateRefresh, CompleteEmailVerification) обязана быть атомарной.
type Store struct {
	mu      sync.Mutex
	users   map[string]authstore.User              // username → User
	byID    map[string]string                      // user ID → username
	byEmail map[string]string                      // email → username
	byKey   map[string]string                      // connect_key → user ID
	refr    map[string]authstore.RefreshToken      // tokenHash → RefreshToken
	verifs  map[string]authstore.EmailVerification // userID → активный код
}

// New создаёт пустое хранилище.
func New() *Store {
	return &Store{
		users:   make(map[string]authstore.User),
		byID:    make(map[string]string),
		byEmail: make(map[string]string),
		byKey:   make(map[string]string),
		refr:    make(map[string]authstore.RefreshToken),
		verifs:  make(map[string]authstore.EmailVerification),
	}
}

// CreateUser создаёт пользователя со случайным ID (email не подтверждён).
func (s *Store) CreateUser(_ context.Context, username, email string, passwordHash []byte) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createUserLocked(username, email, passwordHash)
}

// createUserLocked создаёт пользователя; конфликт имени проверяется
// раньше конфликта email — детерминированно, как в Postgres (там при
// нарушении двух UNIQUE-ограничений сразу репортится users_username_key:
// username объявлен раньше email). Вызывать под s.mu.
func (s *Store) createUserLocked(username, email string, passwordHash []byte) (authstore.User, error) {
	if _, ok := s.users[username]; ok {
		return authstore.User{}, authstore.ErrUserExists
	}
	if _, ok := s.byEmail[email]; ok {
		return authstore.User{}, authstore.ErrEmailExists
	}
	u := authstore.User{
		ID:           newID(),
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
	}
	s.users[username] = u
	s.byID[u.ID] = username
	s.byEmail[u.Email] = username
	return u, nil
}

// CreateUserWithCode атомарно создаёт пользователя и его первый код
// подтверждения: оба словаря меняются под одним локом, частичного
// результата не бывает.
func (s *Store) CreateUserWithCode(_ context.Context, username, email string, passwordHash []byte, codeHash string, codeExpiresAt time.Time) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.createUserLocked(username, email, passwordHash)
	if err != nil {
		return authstore.User{}, err
	}
	s.verifs[u.ID] = authstore.EmailVerification{
		CodeHash:  codeHash,
		UserID:    u.ID,
		ExpiresAt: codeExpiresAt,
		CreatedAt: time.Now(),
	}
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

// GetUserByEmail ищет пользователя по адресу email.
func (s *Store) GetUserByEmail(_ context.Context, email string) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, ok := s.byEmail[email]
	if !ok {
		return authstore.User{}, authstore.ErrUserNotFound
	}
	return s.users[username], nil
}

// GetUserByID ищет пользователя по user_id.
func (s *Store) GetUserByID(_ context.Context, userID string) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, ok := s.byID[userID]
	if !ok {
		return authstore.User{}, authstore.ErrUserNotFound
	}
	return s.users[username], nil
}

// GetUserByConnectKey ищет пользователя по ключу подключения.
func (s *Store) GetUserByConnectKey(_ context.Context, connectKey string) (authstore.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.byKey[connectKey]
	if !ok {
		return authstore.User{}, authstore.ErrUserNotFound
	}
	u, ok := s.users[s.byID[id]]
	if !ok {
		return authstore.User{}, authstore.ErrUserNotFound
	}
	return u, nil
}

// VerifyEmail помечает email пользователя подтверждённым.
func (s *Store) VerifyEmail(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, ok := s.byID[userID]
	if !ok {
		return authstore.ErrUserNotFound
	}
	u := s.users[username]
	u.EmailVerified = true
	s.users[username] = u
	return nil
}

// SetConnectKey назначает пользователю ключ подключения.
func (s *Store) SetConnectKey(_ context.Context, userID, connectKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, ok := s.byID[userID]
	if !ok {
		return authstore.ErrUserNotFound
	}
	if other, clash := s.byKey[connectKey]; clash && other != userID {
		return authstore.ErrConnectKeyExists
	}
	u := s.users[username]
	if u.ConnectKey != "" && u.ConnectKey != connectKey {
		delete(s.byKey, u.ConnectKey)
	}
	u.ConnectKey = connectKey
	s.users[username] = u
	s.byKey[connectKey] = userID
	return nil
}

// SaveRefresh сохраняет запись о refresh-токене.
func (s *Store) SaveRefresh(_ context.Context, tok authstore.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.refr[tok.TokenHash] = tok
	return nil
}

// RotateRefresh атомарно (под общим локом) потребляет старый токен
// и сохраняет новый: побеждает ровно один конкурентный вызов, остальные
// получают ErrRefreshNotFound. Истёкший старый токен — тоже
// ErrRefreshNotFound. Заодно удаляются протухшие записи: их всё равно
// никто не потребит, а копить их в памяти незачем.
func (s *Store) RotateRefresh(_ context.Context, oldTokenHash string, newTok authstore.RefreshToken) (authstore.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for h, tok := range s.refr {
		if now.After(tok.ExpiresAt) {
			delete(s.refr, h)
		}
	}
	old, ok := s.refr[oldTokenHash]
	if !ok || now.After(old.ExpiresAt) {
		if ok {
			delete(s.refr, oldTokenHash)
		}
		return authstore.RefreshToken{}, authstore.ErrRefreshNotFound
	}
	delete(s.refr, oldTokenHash)
	newTok.UserID = old.UserID
	s.refr[newTok.TokenHash] = newTok
	return old, nil
}

// RevokeRefresh удаляет запись; идемпотентна.
func (s *Store) RevokeRefresh(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.refr, tokenHash)
	return nil
}

// SaveEmailVerification сохраняет код подтверждения, замещая предыдущий
// активный код пользователя (счётчик попыток у новой записи обнулён —
// сбрасывается вместе с заменой). Заодно удаляет протухшие коды других
// пользователей: потреблены они не будут, а копить их незачем.
func (s *Store) SaveEmailVerification(_ context.Context, tok authstore.EmailVerification) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, v := range s.verifs {
		if now.After(v.ExpiresAt) {
			delete(s.verifs, id)
		}
	}
	s.verifs[tok.UserID] = tok
	return nil
}

// CompleteEmailVerification атомарно (под общим локом) сверяет
// и потребляет код, помечает email подтверждённым и назначает
// connect_key. Порядок важен: конфликт connect_key проверяется до
// потребления кода, чтобы повтор с другим ключом не сжигал код.
func (s *Store) CompleteEmailVerification(_ context.Context, userID, codeHash, connectKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.verifs[userID]
	if !ok {
		return authstore.ErrVerificationNotFound
	}
	if time.Now().After(tok.ExpiresAt) {
		delete(s.verifs, userID)
		return authstore.ErrVerificationNotFound
	}
	if tok.Attempts >= authstore.MaxVerificationAttempts {
		return authstore.ErrVerificationNotFound
	}
	if tok.CodeHash != codeHash {
		tok.Attempts++
		s.verifs[userID] = tok
		return authstore.ErrVerificationWrongCode
	}
	if other, clash := s.byKey[connectKey]; clash && other != userID {
		return authstore.ErrConnectKeyExists
	}
	username, ok := s.byID[userID]
	if !ok {
		return authstore.ErrUserNotFound
	}
	delete(s.verifs, userID)
	u := s.users[username]
	u.EmailVerified = true
	u.ConnectKey = connectKey
	s.users[username] = u
	s.byKey[connectKey] = userID
	return nil
}

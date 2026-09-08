package authstorememory

import (
	"context"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

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

package authstorememory

import (
	"context"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

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

package authstorememory

import (
	"context"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// SaveOAuthClient сохраняет OAuth-клиента (dynamic registration).
func (s *Store) SaveOAuthClient(_ context.Context, client authstore.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[client.ClientID] = client
	return nil
}

// GetOAuthClient ищет OAuth-клиента по client_id.
func (s *Store) GetOAuthClient(_ context.Context, clientID string) (authstore.OAuthClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, ok := s.clients[clientID]
	if !ok {
		return authstore.OAuthClient{}, authstore.ErrOAuthClientNotFound
	}
	return client, nil
}

// SaveOAuthCode сохраняет код авторизации. Заодно удаляет протухшие
// коды: потреблены они не будут, а копить их в памяти незачем.
func (s *Store) SaveOAuthCode(_ context.Context, code authstore.OAuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for h, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, h)
		}
	}
	s.codes[code.CodeHash] = code
	return nil
}

// ConsumeOAuthCode атомарно (под общим локом) потребляет код:
// побеждает ровно один конкурентный вызов, остальные получают
// ErrOAuthCodeNotFound. Истёкший код — тоже ErrOAuthCodeNotFound.
func (s *Store) ConsumeOAuthCode(_ context.Context, codeHash string) (authstore.OAuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	code, ok := s.codes[codeHash]
	if !ok || time.Now().After(code.ExpiresAt) {
		if ok {
			delete(s.codes, codeHash)
		}
		return authstore.OAuthCode{}, authstore.ErrOAuthCodeNotFound
	}
	delete(s.codes, codeHash)
	return code, nil
}

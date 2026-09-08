package authstorememory

import (
	"context"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

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

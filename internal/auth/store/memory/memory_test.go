package authstorememory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

func TestUsers(t *testing.T) {
	s := New()
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" || u.Username != "alice" {
		t.Fatalf("unexpected user: %+v", u)
	}

	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("id mismatch: %q vs %q", got.ID, u.ID)
	}

	if _, err := s.GetUserByUsername(ctx, "bob"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}

	if _, err := s.CreateUser(ctx, "alice", []byte("hash2")); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("want ErrUserExists, got %v", err)
	}
}

func TestRefreshConsumeOnce(t *testing.T) {
	s := New()
	ctx := context.Background()

	tok := authstore.RefreshToken{
		TokenHash: "h1",
		UserID:    "u1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.SaveRefresh(ctx, tok); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	got, err := s.ConsumeRefresh(ctx, "h1")
	if err != nil {
		t.Fatalf("ConsumeRefresh: %v", err)
	}
	if got.UserID != "u1" {
		t.Fatalf("unexpected token: %+v", got)
	}

	// Повторное потребление — токен одноразовый (ротация = отзыв старого).
	if _, err := s.ConsumeRefresh(ctx, "h1"); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("want ErrRefreshNotFound on second consume, got %v", err)
	}
}

func TestRevokeIdempotent(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.SaveRefresh(ctx, authstore.RefreshToken{TokenHash: "h2"}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}
	if err := s.RevokeRefresh(ctx, "h2"); err != nil {
		t.Fatalf("RevokeRefresh: %v", err)
	}
	// Повторный revoke отсутствующей записи — не ошибка.
	if err := s.RevokeRefresh(ctx, "h2"); err != nil {
		t.Fatalf("second RevokeRefresh: %v", err)
	}
	if _, err := s.ConsumeRefresh(ctx, "h2"); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("want ErrRefreshNotFound after revoke, got %v", err)
	}
}

// TestConsumeRace: при конкурентном потреблении одного токена
// побеждает ровно один вызов.
func TestConsumeRace(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.SaveRefresh(ctx, authstore.RefreshToken{TokenHash: "race"}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	wins := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ConsumeRefresh(ctx, "race"); err == nil {
				wins <- 1
			}
		}()
	}
	wg.Wait()
	close(wins)

	total := 0
	for range wins {
		total++
	}
	if total != 1 {
		t.Fatalf("exactly one consumer must win, got %d", total)
	}
}

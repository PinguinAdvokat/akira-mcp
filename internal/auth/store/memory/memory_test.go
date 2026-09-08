package authstorememory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

func TestUsers(t *testing.T) {
	s := New()
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "alice@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" || u.Username != "alice" || u.Email != "alice@example.com" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if u.EmailVerified {
		t.Fatal("fresh user must not be verified")
	}

	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("id mismatch: %q vs %q", got.ID, u.ID)
	}

	if _, err := s.GetUserByEmail(ctx, "alice@example.com"); err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if _, err := s.GetUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("GetUserByEmail: want ErrUserNotFound, got %v", err)
	}

	if _, err := s.GetUserByUsername(ctx, "bob"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}

	if _, err := s.CreateUser(ctx, "alice", "other@example.com", []byte("hash2")); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("want ErrUserExists, got %v", err)
	}
	if _, err := s.CreateUser(ctx, "alice2", "alice@example.com", []byte("hash2")); !errors.Is(err, authstore.ErrEmailExists) {
		t.Fatalf("want ErrEmailExists, got %v", err)
	}
}

// TestCreateUserConflictDeterminism: при конфликте и имени, и email
// (принадлежат разным пользователям) возвращается ErrUserExists —
// всегда один и тот же сентинел, как в Postgres.
func TestCreateUserConflictDeterminism(t *testing.T) {
	s := New()
	ctx := context.Background()

	if _, err := s.CreateUser(ctx, "alice", "alice@example.com", []byte("hash")); err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	if _, err := s.CreateUser(ctx, "bob", "bob@example.com", []byte("hash")); err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	if _, err := s.CreateUser(ctx, "alice", "bob@example.com", []byte("hash")); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("username+email conflict: want ErrUserExists, got %v", err)
	}
	if _, err := s.CreateUser(ctx, "carol", "alice@example.com", []byte("hash")); !errors.Is(err, authstore.ErrEmailExists) {
		t.Fatalf("email-only conflict: want ErrEmailExists, got %v", err)
	}
}

func TestVerifyAndConnectKey(t *testing.T) {
	s := New()
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "alice", "alice@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// До верификации ключа нет и поиск по нему ничего не находит.
	if _, err := s.GetUserByConnectKey(ctx, "abc12"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound before verification, got %v", err)
	}

	if err := s.VerifyEmail(ctx, u.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if !got.EmailVerified {
		t.Fatal("user must be verified after VerifyEmail")
	}

	if err := s.SetConnectKey(ctx, u.ID, "abc12"); err != nil {
		t.Fatalf("SetConnectKey: %v", err)
	}
	got, err = s.GetUserByConnectKey(ctx, "abc12")
	if err != nil {
		t.Fatalf("GetUserByConnectKey: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("connect key resolved to wrong user: %q vs %q", got.ID, u.ID)
	}

	// Перегенерация: старый ключ перестаёт действовать.
	if err := s.SetConnectKey(ctx, u.ID, "xyz98"); err != nil {
		t.Fatalf("SetConnectKey (regenerate): %v", err)
	}
	if _, err := s.GetUserByConnectKey(ctx, "abc12"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("old connect key must stop working, got %v", err)
	}
	if _, err := s.GetUserByConnectKey(ctx, "xyz98"); err != nil {
		t.Fatalf("new connect key must work, got %v", err)
	}

	// Коллизия ключей между пользователями.
	b, err := s.CreateUser(ctx, "bob", "bob@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.SetConnectKey(ctx, b.ID, "xyz98"); !errors.Is(err, authstore.ErrConnectKeyExists) {
		t.Fatalf("want ErrConnectKeyExists, got %v", err)
	}

	// Неизвестный пользователь.
	if err := s.SetConnectKey(ctx, "nobody", "q1"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
}

// TestCreateUserWithCode: пользователь и первый код создаются атомарно;
// при конфликте не создаётся ни пользователь, ни код.
func TestCreateUserWithCode(t *testing.T) {
	s := New()
	ctx := context.Background()

	u, err := s.CreateUserWithCode(ctx, "alice", "alice@example.com", []byte("hash"), "h1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateUserWithCode: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, "h1", "ck-alice"); err != nil {
		t.Fatalf("CompleteEmailVerification with the issued code: %v", err)
	}
	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if !got.EmailVerified || got.ConnectKey != "ck-alice" {
		t.Fatalf("user must be verified with connect key after completion: %+v", got)
	}

	// Конфликт имени — никакого частичного результата.
	if _, err := s.CreateUserWithCode(ctx, "alice", "other@example.com", []byte("hash"), "h2", time.Now().Add(time.Hour)); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("want ErrUserExists, got %v", err)
	}
	if _, err := s.GetUserByEmail(ctx, "other@example.com"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("failed CreateUserWithCode must not leave a user behind, got %v", err)
	}
}

// TestCompleteEmailVerification: базовая семантика сверки и
// потребления кода — одноразовость, замещение resend'ом.
func TestCompleteEmailVerification(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Неверный код для отсутствующей записи — ErrVerificationNotFound.
	if err := s.CompleteEmailVerification(ctx, "u1", "h-wrong", "k"); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("want ErrVerificationNotFound without saved code, got %v", err)
	}

	u, err := s.CreateUser(ctx, "alice", "alice@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "h1", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	// Второй код замещает первый — активный код один на пользователя.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "h2", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	// Замещённый код — это неверный код для активной записи (попытка
	// засчитывается; наружу — тот же отказ, что и для любого промаха).
	if err := s.CompleteEmailVerification(ctx, u.ID, "h1", "k"); !errors.Is(err, authstore.ErrVerificationWrongCode) {
		t.Fatalf("replaced code must be wrong code, got %v", err)
	}

	// Верный код потребляется ровно один раз.
	if err := s.CompleteEmailVerification(ctx, u.ID, "h2", "k1"); err != nil {
		t.Fatalf("CompleteEmailVerification: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, "h2", "k1"); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("code must be one-time, got %v", err)
	}
}

// TestVerificationAttempts: неверные вводы засчитываются, после
// MaxVerificationAttempts верный код не принимается; resend (новая
// запись) сбрасывает счётчик. Истёкший код не принимается.
func TestVerificationAttempts(t *testing.T) {
	s := New()
	ctx := context.Background()

	a, err := s.CreateUser(ctx, "alice", "a@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	b, err := s.CreateUser(ctx, "bob", "b@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	c, err := s.CreateUser(ctx, "carol", "c@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser carol: %v", err)
	}

	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{
		CodeHash: "h-right", UserID: a.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}

	// Неверный код — ErrVerificationWrongCode, попытка засчитана.
	if err := s.CompleteEmailVerification(ctx, a.ID, "h-wrong", "k"); !errors.Is(err, authstore.ErrVerificationWrongCode) {
		t.Fatalf("want ErrVerificationWrongCode, got %v", err)
	}
	// Верный код всё ещё работает (попытки не исчерпаны).
	if err := s.CompleteEmailVerification(ctx, a.ID, "h-right", "ka"); err != nil {
		t.Fatalf("right code must work before attempts exhausted, got %v", err)
	}

	// Исчерпание попыток: MaxVerificationAttempts промахов — верный код
	// больше не принимается.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{
		CodeHash: "h2", UserID: b.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	for i := 0; i < authstore.MaxVerificationAttempts; i++ {
		if err := s.CompleteEmailVerification(ctx, b.ID, "h-wrong", "k"); !errors.Is(err, authstore.ErrVerificationWrongCode) {
			t.Fatalf("wrong code #%d: want ErrVerificationWrongCode, got %v", i+1, err)
		}
	}
	if err := s.CompleteEmailVerification(ctx, b.ID, "h2", "k"); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("right code must not work after attempts exhausted, got %v", err)
	}

	// Resend: новая запись замещает исчерпанную и сбрасывает счётчик.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{
		CodeHash: "h3", UserID: b.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveEmailVerification (resend): %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, b.ID, "h3", "k"); err != nil {
		t.Fatalf("code after resend must work, got %v", err)
	}

	// Истёкший код не принимается.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{
		CodeHash: "h4", UserID: c.ID, ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, c.ID, "h4", "k"); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("expired code must not work, got %v", err)
	}
}

// TestSharedCodeHash: у двух пользователей может совпасть хеш кода
// (6 цифр — конечное пространство хешей); записи независимы, и потребление
// кода одним пользователем не затрагивает код другого.
func TestSharedCodeHash(t *testing.T) {
	s := New()
	ctx := context.Background()

	a, err := s.CreateUser(ctx, "alice", "a@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	b, err := s.CreateUser(ctx, "bob", "b@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "shared", UserID: a.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveEmailVerification a: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "shared", UserID: b.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveEmailVerification b: %v", err)
	}

	if err := s.CompleteEmailVerification(ctx, a.ID, "shared", "ka"); err != nil {
		t.Fatalf("alice's code must complete: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, b.ID, "shared", "kb"); err != nil {
		t.Fatalf("bob's code must be independent of alice's: %v", err)
	}
}

// TestCompleteClashKeepsCode: конфликт connect_key при завершении
// верификации не сжигает код — повтор с другим ключом проходит.
func TestCompleteClashKeepsCode(t *testing.T) {
	s := New()
	ctx := context.Background()

	other, err := s.CreateUser(ctx, "other", "other@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser other: %v", err)
	}
	if err := s.VerifyEmail(ctx, other.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if err := s.SetConnectKey(ctx, other.ID, "taken"); err != nil {
		t.Fatalf("SetConnectKey: %v", err)
	}

	u, err := s.CreateUser(ctx, "alice", "alice@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "h1", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}

	if err := s.CompleteEmailVerification(ctx, u.ID, "h1", "taken"); !errors.Is(err, authstore.ErrConnectKeyExists) {
		t.Fatalf("want ErrConnectKeyExists, got %v", err)
	}
	// Код не потреблён: повтор с другим ключом завершает верификацию.
	if err := s.CompleteEmailVerification(ctx, u.ID, "h1", "free"); err != nil {
		t.Fatalf("retry with a free key must complete: %v", err)
	}
}

// TestRefreshRotation: старый токен атомарно обменивается на новый,
// user_id наследуется; старый повторно не работает; истёкший — тоже.
func TestRefreshRotation(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: "h1", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	got, err := s.RotateRefresh(ctx, "h1", authstore.RefreshToken{
		TokenHash: "h2", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("RotateRefresh: %v", err)
	}
	if got.UserID != "u1" {
		t.Fatalf("rotated record must carry the old user_id, got %+v", got)
	}

	// Старый потреблён — повтор даёт ErrRefreshNotFound.
	if _, err := s.RotateRefresh(ctx, "h1", authstore.RefreshToken{TokenHash: "h3"}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("want ErrRefreshNotFound on second rotation, got %v", err)
	}
	// Новый ротируется дальше, user_id наследуется от исходного.
	rec, err := s.RotateRefresh(ctx, "h2", authstore.RefreshToken{
		TokenHash: "h3", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("rotate the new token: %v", err)
	}
	if rec.UserID != "u1" {
		t.Fatalf("user_id must be inherited, got %+v", rec)
	}

	// Истёкший старый токен — ErrRefreshNotFound (и не ротируется).
	if err := s.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: "exp", UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}
	if _, err := s.RotateRefresh(ctx, "exp", authstore.RefreshToken{TokenHash: "h4"}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("expired token must not rotate, got %v", err)
	}
	if _, err := s.RotateRefresh(ctx, "h4", authstore.RefreshToken{TokenHash: "h5"}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("new token of the expired rotation must not be saved, got %v", err)
	}
}

func TestRevokeIdempotent(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: "h2", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}
	if err := s.RevokeRefresh(ctx, "h2"); err != nil {
		t.Fatalf("RevokeRefresh: %v", err)
	}
	// Повторный revoke отсутствующей записи — не ошибка.
	if err := s.RevokeRefresh(ctx, "h2"); err != nil {
		t.Fatalf("second RevokeRefresh: %v", err)
	}
	if _, err := s.RotateRefresh(ctx, "h2", authstore.RefreshToken{TokenHash: "h3"}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("want ErrRefreshNotFound after revoke, got %v", err)
	}
}

// TestRotateRace: при конкурентной ротации одного токена побеждает
// ровно один вызов.
func TestRotateRace(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: "race", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	wins := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RotateRefresh(ctx, "race", authstore.RefreshToken{
				TokenHash: fmt.Sprintf("new-%d", i), ExpiresAt: time.Now().Add(time.Hour),
			}); err == nil {
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
		t.Fatalf("exactly one rotator must win, got %d", total)
	}
}

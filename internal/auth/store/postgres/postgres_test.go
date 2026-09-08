package authstorepostgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// newTestStore подключается к тестовой БД, указанной в
// TEST_DATABASE_URL (например, postgres://akira:akira@127.0.0.1:5432/akira).
// Без переменной тесты пропускаются: миграции применяются к целевой БД,
// запускать их на произвольной БД по умолчанию нельзя.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres store integration tests")
	}
	s, err := New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// uniqueSuffix генерирует уникальные значения для повторных прогонов
// (в тестовой БД могут остаться данные с прошлого раза).
func uniqueSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func TestUserLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	u, err := s.CreateUser(ctx, "alice-"+sfx, "alice-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" || u.EmailVerified || u.ConnectKey != "" {
		t.Fatalf("fresh user must be unverified without connect key: %+v", u)
	}

	got, err := s.GetUserByUsername(ctx, u.Username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != u.ID || got.Email != u.Email {
		t.Fatalf("unexpected user: %+v", got)
	}

	if _, err := s.GetUserByEmail(ctx, u.Email); err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if _, err := s.GetUserByEmail(ctx, "nobody-"+sfx+"@example.com"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("GetUserByEmail: want ErrUserNotFound, got %v", err)
	}

	if _, err := s.CreateUser(ctx, u.Username, "other-"+sfx+"@example.com", []byte("h")); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("want ErrUserExists, got %v", err)
	}
	if _, err := s.CreateUser(ctx, "bob-"+sfx, u.Email, []byte("h")); !errors.Is(err, authstore.ErrEmailExists) {
		t.Fatalf("want ErrEmailExists, got %v", err)
	}

	if err := s.VerifyEmail(ctx, u.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	got, err = s.GetUserByUsername(ctx, u.Username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if !got.EmailVerified {
		t.Fatal("user must be verified after VerifyEmail")
	}

	key := "ck" + sfx
	if err := s.SetConnectKey(ctx, u.ID, key); err != nil {
		t.Fatalf("SetConnectKey: %v", err)
	}
	got, err = s.GetUserByConnectKey(ctx, key)
	if err != nil {
		t.Fatalf("GetUserByConnectKey: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("connect key resolved to wrong user: %q vs %q", got.ID, u.ID)
	}

	// Перегенерация: старый ключ перестаёт действовать.
	key2 := "ck2" + sfx
	if err := s.SetConnectKey(ctx, u.ID, key2); err != nil {
		t.Fatalf("SetConnectKey (regenerate): %v", err)
	}
	if _, err := s.GetUserByConnectKey(ctx, key); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("old connect key must stop working, got %v", err)
	}

	// Коллизия ключей.
	b, err := s.CreateUser(ctx, "bob-"+sfx+"b", "bob-"+sfx+"b@example.com", []byte("h"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.SetConnectKey(ctx, b.ID, key2); !errors.Is(err, authstore.ErrConnectKeyExists) {
		t.Fatalf("want ErrConnectKeyExists, got %v", err)
	}
}

// TestCreateUserConflictDeterminism: при конфликте и имени, и email
// (принадлежат разным пользователям) Postgres репортит
// users_username_key — mapError детерминированно даёт ErrUserExists.
func TestCreateUserConflictDeterminism(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	if _, err := s.CreateUser(ctx, "alice-"+sfx, "alice-"+sfx+"@example.com", []byte("h")); err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	if _, err := s.CreateUser(ctx, "bob-"+sfx, "bob-"+sfx+"@example.com", []byte("h")); err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	if _, err := s.CreateUser(ctx, "alice-"+sfx, "bob-"+sfx+"@example.com", []byte("h")); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("username+email conflict: want ErrUserExists, got %v", err)
	}
	if _, err := s.CreateUser(ctx, "carol-"+sfx, "alice-"+sfx+"@example.com", []byte("h")); !errors.Is(err, authstore.ErrEmailExists) {
		t.Fatalf("email-only conflict: want ErrEmailExists, got %v", err)
	}
}

// TestCreateUserWithCode: пользователь и первый код создаются атомарно;
// при конфликте не остаётся ни пользователя, ни кода.
func TestCreateUserWithCode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	u, err := s.CreateUserWithCode(ctx, "carol-"+sfx, "carol-"+sfx+"@example.com", []byte("hash"), "ch-"+sfx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateUserWithCode: %v", err)
	}
	key := "ck-carol-" + sfx
	if err := s.CompleteEmailVerification(ctx, u.ID, "ch-"+sfx, key); err != nil {
		t.Fatalf("CompleteEmailVerification: %v", err)
	}
	got, err := s.GetUserByUsername(ctx, u.Username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if !got.EmailVerified || got.ConnectKey != key {
		t.Fatalf("user must be verified with connect key: %+v", got)
	}

	// Конфликт имени — никакого частичного результата.
	if _, err := s.CreateUserWithCode(ctx, u.Username, "other-"+sfx+"@example.com", []byte("h"), "ch2-"+sfx, time.Now().Add(time.Hour)); !errors.Is(err, authstore.ErrUserExists) {
		t.Fatalf("want ErrUserExists, got %v", err)
	}
	if _, err := s.GetUserByEmail(ctx, "other-"+sfx+"@example.com"); !errors.Is(err, authstore.ErrUserNotFound) {
		t.Fatalf("failed CreateUserWithCode must not leave a user behind, got %v", err)
	}
}

// TestRefreshRotation: старый токен атомарно обменивается на новый,
// user_id наследуется; повтор и истёкший токен — ErrRefreshNotFound,
// причём новый токен истёкшей ротации не сохраняется.
func TestRefreshRotation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	u, err := s.CreateUser(ctx, "dave-"+sfx, "dave-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	old := authstore.RefreshToken{TokenHash: "rh1-" + sfx, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	if err := s.SaveRefresh(ctx, old); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	got, err := s.RotateRefresh(ctx, old.TokenHash, authstore.RefreshToken{
		TokenHash: "rh2-" + sfx, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("RotateRefresh: %v", err)
	}
	if got.UserID != u.ID {
		t.Fatalf("rotated record must carry the old user_id, got %+v", got)
	}

	// Старый потреблён — повтор даёт ErrRefreshNotFound.
	if _, err := s.RotateRefresh(ctx, old.TokenHash, authstore.RefreshToken{TokenHash: "rh3-" + sfx}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("want ErrRefreshNotFound on second rotation, got %v", err)
	}
	// Новый ротируется дальше, user_id наследуется.
	rec, err := s.RotateRefresh(ctx, "rh2-"+sfx, authstore.RefreshToken{
		TokenHash: "rh3-" + sfx, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("rotate the new token: %v", err)
	}
	if rec.UserID != u.ID {
		t.Fatalf("user_id must be inherited, got %+v", rec)
	}

	// Revoke идемпотентен; после него токен не ротируется.
	if err := s.RevokeRefresh(ctx, "rh3-"+sfx); err != nil {
		t.Fatalf("RevokeRefresh: %v", err)
	}
	if err := s.RevokeRefresh(ctx, "rh3-"+sfx); err != nil {
		t.Fatalf("second RevokeRefresh: %v", err)
	}
	if _, err := s.RotateRefresh(ctx, "rh3-"+sfx, authstore.RefreshToken{TokenHash: "rh4-" + sfx}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("want ErrRefreshNotFound after revoke, got %v", err)
	}

	// Истёкший токен не ротируется, новый при этом не сохраняется.
	if err := s.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: "exp-" + sfx, UserID: u.ID, ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveRefresh (expired): %v", err)
	}
	if _, err := s.RotateRefresh(ctx, "exp-"+sfx, authstore.RefreshToken{
		TokenHash: "rh4-" + sfx, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("expired token must not rotate, got %v", err)
	}
	if _, err := s.RotateRefresh(ctx, "rh4-"+sfx, authstore.RefreshToken{TokenHash: "rh5-" + sfx}); !errors.Is(err, authstore.ErrRefreshNotFound) {
		t.Fatalf("new token of the expired rotation must not be saved, got %v", err)
	}
}

// TestRotateRace: при конкурентной ротации одного токена побеждает
// ровно один вызов (DELETE … RETURNING под транзакцией).
func TestRotateRace(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	if err := s.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: "race-" + sfx, UserID: "u-" + sfx, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveRefresh: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	wins := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RotateRefresh(ctx, "race-"+sfx, authstore.RefreshToken{
				TokenHash: fmt.Sprintf("race-new-%d-%s", i, sfx), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
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

// TestVerificationComplete: одноразовость кода, замещение resend'ом,
// счётчик попыток и истечение.
func TestVerificationComplete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	u, err := s.CreateUser(ctx, "erin-"+sfx, "erin-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Кода нет — ErrVerificationNotFound.
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh-x-"+sfx, "k-"+sfx); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("want ErrVerificationNotFound without saved code, got %v", err)
	}

	// Второй код замещает первый — активный код один на пользователя.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "vh1-" + sfx, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "vh2-" + sfx, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification (replace): %v", err)
	}
	// Замещённый код — неверный код для активной записи (попытка
	// засчитывается; наружу — тот же отказ, что и для любого промаха).
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh1-"+sfx, "k1-"+sfx); !errors.Is(err, authstore.ErrVerificationWrongCode) {
		t.Fatalf("replaced code must be wrong code, got %v", err)
	}
	// Верный код потребляется ровно один раз.
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh2-"+sfx, "k1-"+sfx); err != nil {
		t.Fatalf("CompleteEmailVerification: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh2-"+sfx, "k1-"+sfx); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("code must be one-time, got %v", err)
	}
	got, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !got.EmailVerified || got.ConnectKey != "k1-"+sfx {
		t.Fatalf("user must be verified with connect key, got %+v", got)
	}

	// Попытки: один промах не сжигает код.
	right := "vh3-" + sfx
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: right, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh-wrong-"+sfx, "k2-"+sfx); !errors.Is(err, authstore.ErrVerificationWrongCode) {
		t.Fatalf("want ErrVerificationWrongCode, got %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, right, "k2-"+sfx); err != nil {
		t.Fatalf("right code must work after one miss, got %v", err)
	}

	// Исчерпание попыток: верный код больше не принимается.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: right, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}
	for i := 0; i < authstore.MaxVerificationAttempts; i++ {
		if err := s.CompleteEmailVerification(ctx, u.ID, "vh-wrong-"+sfx, "k3-"+sfx); !errors.Is(err, authstore.ErrVerificationWrongCode) {
			t.Fatalf("wrong code #%d: want ErrVerificationWrongCode, got %v", i+1, err)
		}
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, right, "k3-"+sfx); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("right code must not work after attempts exhausted, got %v", err)
	}

	// Resend: новая запись сбрасывает счётчик.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "vh4-" + sfx, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification (resend): %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh4-"+sfx, "k3-"+sfx); err != nil {
		t.Fatalf("code after resend must work, got %v", err)
	}

	// Истёкший код не принимается.
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "vh5-" + sfx, UserID: u.ID, ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification (expired): %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh5-"+sfx, "k4-"+sfx); !errors.Is(err, authstore.ErrVerificationNotFound) {
		t.Fatalf("expired code must not work, got %v", err)
	}
}

// TestSharedCodeHash: у двух пользователей может совпасть хеш кода
// (6 цифр — конечное пространство хешей); до миграции 0003 (PK на
// token_hash) второй INSERT падал с unique_violation. Записи независимы:
// потребление кода одним не затрагивает код другого.
func TestSharedCodeHash(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	a, err := s.CreateUser(ctx, "frank-"+sfx, "frank-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser frank: %v", err)
	}
	b, err := s.CreateUser(ctx, "grace-"+sfx, "grace-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser grace: %v", err)
	}

	shared := "shared-" + sfx
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: shared, UserID: a.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification a: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: shared, UserID: b.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification b (shared hash): %v", err)
	}

	if err := s.CompleteEmailVerification(ctx, a.ID, shared, "ck-a-"+sfx); err != nil {
		t.Fatalf("frank's code must complete: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, b.ID, shared, "ck-b-"+sfx); err != nil {
		t.Fatalf("grace's code must be independent of frank's: %v", err)
	}
}

// TestCompleteClashKeepsCode: конфликт connect_key при завершении
// верификации не сжигает код — повтор с другим ключом проходит.
func TestCompleteClashKeepsCode(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix()

	other, err := s.CreateUser(ctx, "henry-"+sfx, "henry-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser henry: %v", err)
	}
	if err := s.VerifyEmail(ctx, other.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	taken := "taken-" + sfx
	if err := s.SetConnectKey(ctx, other.ID, taken); err != nil {
		t.Fatalf("SetConnectKey: %v", err)
	}

	u, err := s.CreateUser(ctx, "iris-"+sfx, "iris-"+sfx+"@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser iris: %v", err)
	}
	if err := s.SaveEmailVerification(ctx, authstore.EmailVerification{CodeHash: "vh-"+sfx, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SaveEmailVerification: %v", err)
	}

	if err := s.CompleteEmailVerification(ctx, u.ID, "vh-"+sfx, taken); !errors.Is(err, authstore.ErrConnectKeyExists) {
		t.Fatalf("want ErrConnectKeyExists, got %v", err)
	}
	// Код не потреблён: повтор со свободным ключом завершает верификацию.
	if err := s.CompleteEmailVerification(ctx, u.ID, "vh-"+sfx, "free-"+sfx); err != nil {
		t.Fatalf("retry with a free key must complete: %v", err)
	}
}

// execAdmin выполняет административный запрос (CREATE/DROP DATABASE)
// по URL тестовой БД.
func execAdmin(databaseURL, query string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctx, query)
	return err
}

// withDatabase заменяет имя базы в URL-подобном database URL.
func withDatabase(base, name string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" {
		return "", fmt.Errorf("not a URL: %q", base)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// TestConcurrentFreshStart: два процесса одновременно подключаются
// к чистой БД — миграции применяются ровно один раз (advisory-лок;
// раньше check-then-apply гонился между стартерами и проигравший
// падал). Затем смоук новой схемы: одинаковый хеш кода у двух
// пользователей не конфликтует (PK email_verifications — user_id).
func TestConcurrentFreshStart(t *testing.T) {
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping Postgres store integration tests")
	}
	dbName := fmt.Sprintf("akira_mcp_test_%d", time.Now().UnixNano())
	if err := execAdmin(adminURL, fmt.Sprintf("CREATE DATABASE %s", pgx.Identifier{dbName}.Sanitize())); err != nil {
		t.Skipf("cannot create scratch database %s (%v); skipping", dbName, err)
	}
	t.Cleanup(func() {
		_ = execAdmin(adminURL, fmt.Sprintf("DROP DATABASE IF EXISTS %s", pgx.Identifier{dbName}.Sanitize()))
	})

	freshURL, err := withDatabase(adminURL, dbName)
	if err != nil {
		t.Skipf("%v; skipping", err)
	}

	const starters = 2
	errs := make(chan error, starters)
	for i := 0; i < starters; i++ {
		go func() {
			s, err := New(context.Background(), freshURL)
			if err != nil {
				errs <- err
				return
			}
			s.Close()
			errs <- nil
		}()
	}
	for i := 0; i < starters; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent start: %v", err)
		}
	}

	// Смоук чистой схемы.
	s, err := New(context.Background(), freshURL)
	if err != nil {
		t.Fatalf("connect to fresh database: %v", err)
	}
	t.Cleanup(s.Close)
	ctx := context.Background()

	a, err := s.CreateUserWithCode(ctx, "alice", "alice@example.com", []byte("hash"), "code-hash", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateUserWithCode alice: %v", err)
	}
	b, err := s.CreateUserWithCode(ctx, "bob", "bob@example.com", []byte("hash"), "code-hash", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateUserWithCode bob: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, a.ID, "code-hash", "ck-alice"); err != nil {
		t.Fatalf("alice complete: %v", err)
	}
	if err := s.CompleteEmailVerification(ctx, b.ID, "code-hash", "ck-bob"); err != nil {
		t.Fatalf("shared code hash must not conflict after the user_id PK: %v", err)
	}
}

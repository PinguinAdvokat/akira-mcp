package connection

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	akiraconnection "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authstorememory "github.com/PinguinAdvokat/akira-mcp/internal/auth/store/memory"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// testClientID — фиксированный client_id для проверки того, что
// при переподключении connection_id не меняется.
const testClientID = "test-client"

// testConnectKey — ключ тестового пользователя (фиксирован: сервер
// e2e-тестов использует in-memory стор с предзаписанным пользователем).
const testConnectKey = "testkey"

// memLookup — UserLookup поверх in-memory стора для e2e-тестов.
type memLookup struct {
	store *authstorememory.Store
}

// LookupConnectKey находит пользователя по ключу подключения.
// «Пользователь не найден» транслируется в ErrUnknownConnectKey —
// как это делают адаптеры в cmd-пакетах (стор про сентинел сервера
// не знает).
func (l memLookup) LookupConnectKey(ctx context.Context, connectKey string) (string, bool, error) {
	user, err := l.store.GetUserByConnectKey(ctx, connectKey)
	if err != nil {
		if errors.Is(err, authstore.ErrUserNotFound) {
			return "", false, connectionserver.ErrUnknownConnectKey
		}
		return "", false, err
	}
	return user.ID, user.EmailVerified, nil
}

// flakyLookup — UserLookup, который по флагу возвращает транзиентную
// ошибку (имитация недоступной БД) и считает вызовы.
type flakyLookup struct {
	inner memLookup
	mu    sync.Mutex
	down  bool
	calls int
}

// setDown переключает «недоступность БД».
func (l *flakyLookup) setDown(down bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.down = down
}

// callCount возвращает число вызовов поиска.
func (l *flakyLookup) callCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// LookupConnectKey: при «недоступности» — ошибка стора как есть
// (сервер обязан отобразить её в Internal, а не в Unauthenticated).
func (l *flakyLookup) LookupConnectKey(ctx context.Context, connectKey string) (string, bool, error) {
	l.mu.Lock()
	l.calls++
	down := l.down
	l.mu.Unlock()
	if down {
		return "", false, errors.New("db: connection refused")
	}
	return l.inner.LookupConnectKey(ctx, connectKey)
}

// startServer поднимает in-process gRPC-сервер с тестовым пользователем
// (email подтверждён, testConnectKey) и возвращает пул для отправки
// задач, адрес для Config и ожидаемый connection_id ({user_id}:{client_id}).
func startServer(t *testing.T) (*connectionpool.ConnectionPool, string, string) {
	t.Helper()

	store := authstorememory.New()
	userID := seedTestUser(t, store)

	pool := connectionpool.New(0) // без лимита подключений
	grpcServer := connectionserver.NewGRPCServer(pool, memLookup{store: store})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return pool, lis.Addr().String(), userID + ":" + testClientID
}

// seedTestUser создаёт в сторе верифицированного пользователя
// с ключом testConnectKey и возвращает его user_id (генерируется
// стором, фиксированным сделать нельзя).
func seedTestUser(t *testing.T, store *authstorememory.Store) string {
	t.Helper()
	ctx := context.Background()
	u, err := store.CreateUser(ctx, "tester", "tester@example.com", []byte("hash"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.VerifyEmail(ctx, u.ID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if err := store.SetConnectKey(ctx, u.ID, testConnectKey); err != nil {
		t.Fatalf("SetConnectKey: %v", err)
	}
	return u.ID
}

// waitRegistered ждёт, пока подключение зарегистрируется в пуле.
func waitRegistered(t *testing.T, pool *connectionpool.ConnectionPool, connID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pool.Has(connID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("client did not register within 5s")
}

// waitUnregistered ждёт, пока сервер уберёт подключение из пула.
func waitUnregistered(t *testing.T, pool *connectionpool.ConnectionPool, connID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pool.Has(connID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("connection was not dropped within 5s")
}

// selfSignedCert выпускает самоподписанный сертификат с SAN 127.0.0.1
// для TLS-тестов (серверный код не трогаем: listener оборачивается
// в tls.NewListener, grpc-go принимает уже установленные коннекты).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSServer поднимает in-process gRPC-сервер, как startServer,
// но listener обёрнут в TLS с самоподписанным сертификатом.
func startTLSServer(t *testing.T) (*connectionpool.ConnectionPool, string, string) {
	t.Helper()

	store := authstorememory.New()
	userID := seedTestUser(t, store)

	pool := connectionpool.New(0) // без лимита подключений
	grpcServer := connectionserver.NewGRPCServer(pool, memLookup{store: store})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLis := tls.NewListener(lis, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{"h2"},
	})
	go func() { _ = grpcServer.Serve(tlsLis) }()
	t.Cleanup(grpcServer.Stop)

	return pool, tlsLis.Addr().String(), userID + ":" + testClientID
}

// TestTLSConnect: клиент с TLS-конфигурацией регистрируется через
// TLS-листенер и исполняет задачи; конфигурация с nil TLS (все старые
// тесты) по-прежнему ходит plaintext.
func TestTLSConnect(t *testing.T) {
	pool, addr, connID := startTLSServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Run(ctx, Config{
			ServerAddr: addr,
			ClientID:   testClientID,
			ConnectKey: testConnectKey,
			// Самоподписанный серт без CA — проверку пропускаем,
			// но сам TLS-handshake обязан пройти.
			TLS: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // тест
		})
	}()
	waitRegistered(t, pool, connID)

	res, err := pool.SendTask(context.Background(), connID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo tls"}},
	})
	if err != nil {
		t.Fatalf("send task: %v", err)
	}
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("status = %v, want STATUS_OK (error: %s, stderr: %s)", res.Status, res.Error, res.Stderr)
	}
	if string(res.Stdout) != "tls\n" {
		t.Fatalf("stdout = %q, want %q", res.Stdout, "tls\n")
	}
}

// TestTLSVerificationFailureNotFatal: клиент с проверкой сертификата
// (системные CA) против самоподписанного серта не регистрируется,
// но и не выходит — ошибка handshake транзиентна, клиент продолжает
// попытки.
func TestTLSVerificationFailureNotFatal(t *testing.T) {
	pool, addr, connID := startTLSServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			ServerAddr: addr,
			ClientID:   testClientID,
			ConnectKey: testConnectKey,
			RetryDelay: 50 * time.Millisecond,
			// Проверка по системным CA: самоподписанный серт
			// не пройдёт её.
			TLS: &tls.Config{},
		})
	}()

	// Несколько попыток handshake провалились, клиент жив.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			t.Fatalf("client must not exit on TLS handshake failure: %v", err)
		default:
		}
		if pool.Has(connID) {
			t.Fatal("client unexpectedly registered with an untrusted certificate")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestExecTask проверяет полный цикл: регистрация → задача → результат.
func TestExecTask(t *testing.T) {
	pool, addr, connID := startServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Config{ServerAddr: addr, ClientID: testClientID, ConnectKey: testConnectKey}) }()
	waitRegistered(t, pool, connID)

	res, err := pool.SendTask(context.Background(), connID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo hello"}},
	})
	if err != nil {
		t.Fatalf("send task: %v", err)
	}
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("status = %v, want STATUS_OK (error: %s, stderr: %s)", res.Status, res.Error, res.Stderr)
	}
	if string(res.Stdout) != "hello\n" {
		t.Fatalf("stdout = %q, want %q", res.Stdout, "hello\n")
	}
}

// TestDisconnectFailsPendingTask: при разрыве соединения во время
// исполнения долгой задачи ждущий SendTask получает ErrConnectionClosed
// (результата можно не ждать), при этом задача на клиенте не прерывается
// и дописывает маркерный файл. После переподключения клиент доставляет
// сохранённый результат — сервер отбрасывает его молча (никто не ждёт),
// и новые задачи исполняются.
func TestDisconnectFailsPendingTask(t *testing.T) {
	pool, addr, connID := startServer(t)

	marker := filepath.Join(t.TempDir(), "marker")
	cmd := "sleep 1 && echo done > " + marker

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Run(ctx, Config{
			ServerAddr: addr,
			ClientID:   testClientID,
			ConnectKey: testConnectKey,
			RetryDelay: 100 * time.Millisecond,
		})
	}()
	waitRegistered(t, pool, connID)

	// Задача уходит клиенту; ждём, пока она начнёт исполняться,
	// затем рвём соединение со стороны сервера.
	resCh := make(chan *pb.TaskResult, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := pool.SendTask(context.Background(), connID, &pb.Task{
			Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: cmd}},
		})
		resCh <- res
		errCh <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if !pool.Disconnect(connID) {
		t.Fatal("client was not connected at disconnect")
	}

	// Ожидание задачи завершается ошибкой, а не висит вечно.
	select {
	case err := <-errCh:
		if !errors.Is(err, akiraconnection.ErrConnectionClosed) {
			t.Fatalf("send task error = %v, want ErrConnectionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendTask did not return after the connection was lost")
	}

	// Клиент переподключается и снова исполняет задачи.
	waitRegistered(t, pool, connID)
	res, err := pool.SendTask(context.Background(), connID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo again"}},
	})
	if err != nil {
		t.Fatalf("send task after reconnect: %v", err)
	}
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("status after reconnect = %v (error: %s)", res.Status, res.Error)
	}

	// Задача не прерывалась: процесс дописал файл (сохранённый результат
	// доставлен после переподключения и отброшен сервером молча).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, err := os.ReadFile(marker); err == nil {
			if string(data) != "done\n" {
				t.Fatalf("marker content = %q, want %q", data, "done\n")
			}
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("marker not created within 5s: task was interrupted by disconnect")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReconnectSameClientID проверяет, что после разрыва клиент
// переподключается с тем же connect_key и client_id (connection_id
// не меняется) и снова исполняет задачи.
func TestReconnectSameClientID(t *testing.T) {
	pool, addr, connID := startServer(t)

	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() { _ = Run(ctx1, Config{ServerAddr: addr, ClientID: testClientID, ConnectKey: testConnectKey}) }()
	waitRegistered(t, pool, connID)

	res, err := pool.SendTask(context.Background(), connID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo one"}},
	})
	if err != nil || res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("first session: res=%v err=%v", res.GetStatus(), err)
	}

	// Разрываем соединение и ждём, пока сервер освободит connection_id.
	cancel1()
	waitUnregistered(t, pool, connID)

	// Переподключение с тем же connect_key и client_id.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = Run(ctx2, Config{ServerAddr: addr, ClientID: testClientID, ConnectKey: testConnectKey}) }()
	waitRegistered(t, pool, connID)

	res, err = pool.SendTask(context.Background(), connID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo two"}},
	})
	if err != nil {
		t.Fatalf("send task after reconnect: %v", err)
	}
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("status after reconnect = %v (error: %s)", res.Status, res.Error)
	}
	if string(res.Stdout) != "two\n" {
		t.Fatalf("stdout = %q, want %q", res.Stdout, "two\n")
	}
}

// TestBadConnectKeyIsFatal: неизвестный connect_key — постоянная ошибка
// (Unauthenticated): клиент завершается с ошибкой вместо бесконечных
// переподключений с заведомо нерабочим ключом.
func TestBadConnectKeyIsFatal(t *testing.T) {
	_, addr, _ := startServer(t)

	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		done <- Run(ctx, Config{
			ServerAddr: addr,
			ClientID:   testClientID,
			ConnectKey: "wrong",
			RetryDelay: 100 * time.Millisecond,
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run must fail with a bad connect key")
		}
		// Причина выхода — именно Unauthenticated от Connect, а не
		// отмена ctx или иная ошибка (ошибка обёрнута, поэтому код
		// достаём через errors.As по GRPCStatus).
		var grpcErr interface{ GRPCStatus() *status.Status }
		if !errors.As(err, &grpcErr) || grpcErr.GRPCStatus().Code() != codes.Unauthenticated {
			t.Fatalf("Run error = %v, want gRPC Unauthenticated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not give up on a bad connect key within 5s")
	}
}

// TestTransientLookupErrorIsNotFatal: недоступная БД при подключении —
// Internal, а не Unauthenticated: клиент продолжает попытки и
// регистрируется, как только БД оживает. Раньше любая ошибка поиска
// ключа превращалась в Unauthenticated и клиент завершался.
func TestTransientLookupErrorIsNotFatal(t *testing.T) {
	store := authstorememory.New()
	userID := seedTestUser(t, store)
	lookup := &flakyLookup{inner: memLookup{store: store}}
	lookup.setDown(true)

	pool := connectionpool.New(0) // без лимита подключений
	grpcServer := connectionserver.NewGRPCServer(pool, lookup)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)
	connID := userID + ":" + testClientID

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			ServerAddr: lis.Addr().String(),
			ClientID:   testClientID,
			ConnectKey: testConnectKey,
			RetryDelay: 50 * time.Millisecond,
		})
	}()

	// Клиент стучится и получает Internal — и не выходит.
	deadline := time.Now().Add(5 * time.Second)
	for lookup.callCount() < 2 {
		if !time.Now().Before(deadline) {
			t.Fatalf("client retried only %d times", lookup.callCount())
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-runErr:
		t.Fatalf("client must not exit while the lookup is failing: %v", err)
	default:
	}

	// БД «поднялась» — клиент регистрируется и исполняет задачи.
	lookup.setDown(false)
	waitRegistered(t, pool, connID)
	res, err := pool.SendTask(context.Background(), connID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo recovered"}},
	})
	if err != nil {
		t.Fatalf("send task after lookup recovery: %v", err)
	}
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("status = %v, want STATUS_OK (error: %s)", res.Status, res.Error)
	}
}

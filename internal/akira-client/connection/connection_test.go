package connection

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	connection "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	connectionpool "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/pool"
	connectionserver "github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/server"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// testClientID — фиксированный client_id для проверки того, что
// при переподключении id подключения не меняется.
const testClientID = "test-client"

// startServer поднимает in-process gRPC-сервер и возвращает пул
// для отправки задач и адрес для Config.
func startServer(t *testing.T) (*connectionpool.ConnectionPool, string) {
	t.Helper()

	pool := connectionpool.New()
	grpcServer := grpc.NewServer()
	pb.RegisterConnectionServiceServer(grpcServer, connectionserver.New(pool))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return pool, lis.Addr().String()
}

// waitRegistered ждёт, пока клиент зарегистрируется, отправляя
// пробную задачу.
func waitRegistered(t *testing.T, pool *connectionpool.ConnectionPool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, err := pool.SendTask(ctx, testClientID, &pb.Task{
			Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "true"}},
		})
		cancel()
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("client did not register within 5s")
}

// waitUnregistered ждёт, пока сервер уберёт подключение из пула.
func waitUnregistered(t *testing.T, pool *connectionpool.ConnectionPool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, err := pool.SendTask(ctx, testClientID, &pb.Task{
			Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "true"}},
		})
		cancel()
		if errors.Is(err, connection.ErrConnectionNotFound) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("connection was not dropped within 5s")
}

// TestExecTask проверяет полный цикл: регистрация → задача → результат.
func TestExecTask(t *testing.T) {
	pool, addr := startServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Config{ServerAddr: addr, ClientID: testClientID}) }()
	waitRegistered(t, pool)

	res, err := pool.SendTask(context.Background(), testClientID, &pb.Task{
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

// TestTaskSurvivesDisconnect проверяет, что при разрыве соединения
// выполняемая задача не прерывается: процесс дописывает файл,
// хотя соединение уже закрыто.
func TestTaskSurvivesDisconnect(t *testing.T) {
	pool, addr := startServer(t)

	marker := filepath.Join(t.TempDir(), "marker")
	cmd := "sleep 1 && echo done > " + marker

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = Run(ctx, Config{ServerAddr: addr, ClientID: testClientID}) }()
	waitRegistered(t, pool)

	// Задача уходит клиенту; ждём, пока она начнёт исполняться,
	// затем рвём соединение со стороны клиента.
	resCh := make(chan *pb.TaskResult, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := pool.SendTask(context.Background(), testClientID, &pb.Task{
			Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: cmd}},
		})
		resCh <- res
		errCh <- err
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()

	// Сервер будит ждущий SendTask: либо результатом STATUS_ERROR,
	// либо ошибкой разрыва соединения.
	select {
	case res := <-resCh:
		err := <-errCh
		if err == nil && res.Status != pb.TaskResult_STATUS_ERROR {
			t.Fatalf("expected STATUS_ERROR after disconnect, got: %v", res.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendTask did not return after the connection was lost")
	}

	// Задача не прервалась: процесс дописал файл уже без соединения.
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(marker)
		if err == nil {
			if string(data) != "done\n" {
				t.Fatalf("marker content = %q, want %q", data, "done\n")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("task was interrupted by the disconnect: marker not created")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestReconnectSameClientID проверяет, что после разрыва клиент
// переподключается с тем же client_id и снова исполняет задачи.
func TestReconnectSameClientID(t *testing.T) {
	pool, addr := startServer(t)

	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() { _ = Run(ctx1, Config{ServerAddr: addr, ClientID: testClientID}) }()
	waitRegistered(t, pool)

	res, err := pool.SendTask(context.Background(), testClientID, &pb.Task{
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "echo one"}},
	})
	if err != nil || res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("first session: res=%v err=%v", res.GetStatus(), err)
	}

	// Разрываем соединение и ждём, пока сервер освободит client_id.
	cancel1()
	waitUnregistered(t, pool)

	// Переподключение с тем же client_id.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = Run(ctx2, Config{ServerAddr: addr, ClientID: testClientID}) }()
	waitRegistered(t, pool)

	res, err = pool.SendTask(context.Background(), testClientID, &pb.Task{
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

package connectionpool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// execTask — задача без таймаута для тестов.
func execTask(id string) *pb.Task {
	return &pb.Task{
		Id:      id,
		Payload: &pb.Task_Exec{Exec: &pb.ExecTask{Cmd: "true"}},
	}
}

// TestSendTaskFailsWhenTaskNeverSent: если подключение закрылось, пока
// сообщение о задаче не ушло клиенту, SendTask возвращает
// ErrConnectionClosed, а не ждёт результата вечно.
func TestSendTaskFailsWhenTaskNeverSent(t *testing.T) {
	pool := New()
	conn, err := pool.Register("c1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Писателя потока нет — сообщение остаётся в очереди подключения.
		if _, err := pool.SendTask(context.Background(), "c1", execTask("")); err == nil || !errors.Is(err, connection.ErrConnectionClosed) {
			t.Errorf("SendTask error = %v, want ErrConnectionClosed", err)
		}
	}()

	// Даём SendTask поставить сообщение в очередь, затем рвём
	// подключение: клиент задачу не получил, результата не будет.
	time.Sleep(50 * time.Millisecond)
	pool.Unregister(conn)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SendTask did not return after the connection was closed")
	}
}

// TestSendTaskFailsWhenTaskSent: задача успела уйти клиенту (писатель
// забрал сообщение из очереди), но подключение потеряно — SendTask
// возвращает ErrConnectionClosed, а не ждёт результата вечно.
func TestSendTaskFailsWhenTaskSent(t *testing.T) {
	pool := New()
	conn, err := pool.Register("c1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := pool.SendTask(context.Background(), "c1", execTask("sent-task"))
		done <- err
	}()

	// Писатель потока забирает сообщение из очереди — задача «ушла»
	// клиенту, SendTask ждёт результата.
	select {
	case <-conn.Out():
	case <-time.After(time.Second):
		t.Fatal("task message was not queued")
	}

	// Подключение потеряно — результата можно не ждать.
	pool.Disconnect("c1")
	select {
	case err := <-done:
		if !errors.Is(err, connection.ErrConnectionClosed) {
			t.Fatalf("SendTask error = %v, want ErrConnectionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendTask did not return after the connection was lost")
	}
}

// TestSendTaskDuplicateID: повторная отправка задачи с тем же task_id,
// пока первая ждёт результата, возвращает ErrTaskAlreadyPending
// и не затирает ожидание первой.
func TestSendTaskDuplicateID(t *testing.T) {
	pool := New()
	conn, err := pool.Register("c1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := pool.SendTask(context.Background(), "c1", execTask("dup-task"))
		first <- err
	}()
	time.Sleep(50 * time.Millisecond) // ждём регистрации записи в pending

	if _, err := pool.SendTask(context.Background(), "c1", execTask("dup-task")); !errors.Is(err, connection.ErrTaskAlreadyPending) {
		t.Fatalf("second SendTask error = %v, want ErrTaskAlreadyPending", err)
	}

	// Закрытие подключения завершает первое ожидание (задача не ушла).
	pool.Unregister(conn)
	select {
	case err := <-first:
		if !errors.Is(err, connection.ErrConnectionClosed) {
			t.Fatalf("first SendTask error = %v, want ErrConnectionClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first SendTask did not return after the connection was closed")
	}
}

// TestSendTaskTaskTimeout: таймаут задачи (task.timeout_ms) — это
// STATUS_TIMEOUT, а не ошибка.
func TestSendTaskTaskTimeout(t *testing.T) {
	pool := New()
	conn, err := pool.Register("c1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer pool.Unregister(conn)

	task := execTask("")
	task.TimeoutMs = 50
	res, err := pool.SendTask(context.Background(), "c1", task)
	if err != nil {
		t.Fatalf("SendTask: %v", err)
	}
	if res.Status != pb.TaskResult_STATUS_TIMEOUT {
		t.Fatalf("status = %v, want STATUS_TIMEOUT", res.Status)
	}
}

// TestSendTaskCallerDeadline: истечение дедлайна ctx вызывающего кода —
// это ошибка ctx, а не STATUS_TIMEOUT (который означает таймаут самой
// задачи и при nil error неотличим от настоящего результата).
func TestSendTaskCallerDeadline(t *testing.T) {
	pool := New()
	conn, err := pool.Register("c1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer pool.Unregister(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res, err := pool.SendTask(ctx, "c1", execTask(""))
	if err == nil {
		t.Fatalf("expected ctx error, got result %v", res)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

// TestHandleResultRejectsNonOwner: результат от чужого клиента
// отбрасывается (ErrNotTaskOwner), ожидание владельца продолжается
// и завершается его собственным результатом.
func TestHandleResultRejectsNonOwner(t *testing.T) {
	pool := New()
	conn, err := pool.Register("c1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer pool.Unregister(conn)

	resCh := make(chan *pb.TaskResult, 1)
	go func() {
		res, err := pool.SendTask(context.Background(), "c1", execTask("own-task"))
		if err != nil {
			t.Errorf("SendTask: %v", err)
			return
		}
		resCh <- res
	}()
	time.Sleep(50 * time.Millisecond) // ждём регистрации записи в pending

	if err := pool.HandleResult(&pb.TaskResult{TaskId: "own-task", ClientId: "c2", Status: pb.TaskResult_STATUS_OK}); !errors.Is(err, connection.ErrNotTaskOwner) {
		t.Fatalf("HandleResult error = %v, want ErrNotTaskOwner", err)
	}

	// Результат настоящего владельца доставляется.
	if err := pool.HandleResult(&pb.TaskResult{TaskId: "own-task", ClientId: "c1", Status: pb.TaskResult_STATUS_OK}); err != nil {
		t.Fatalf("owner result rejected: %v", err)
	}
	select {
	case res := <-resCh:
		if res.Status != pb.TaskResult_STATUS_OK {
			t.Fatalf("status = %v, want STATUS_OK", res.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("owner result was not delivered")
	}
}

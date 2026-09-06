// Package executor исполняет задачи, полученные от сервера.
package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// Execute исполняет задачу и возвращает TaskResult с task_id и duration.
// Исполнение не зависит от соединения с сервером: ctx привязан только
// к таймауту задачи, поэтому разрыв соединения не прерывает задачу.
func Execute(task *pb.Task) *pb.TaskResult {
	start := time.Now()

	ctx := context.Background()
	if task.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(task.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	var res *pb.TaskResult
	switch payload := task.Payload.(type) {
	case *pb.Task_Exec:
		res = execTask(ctx, payload.Exec)
	case *pb.Task_ReadFile:
		res = readTask(ctx, payload.ReadFile)
	case *pb.Task_WriteFile:
		res = writeTask(ctx, payload.WriteFile)
	default:
		res = errResult(errors.New("unknown task type"))
	}

	if ctx.Err() != nil {
		res.Status = pb.TaskResult_STATUS_TIMEOUT
		res.Error = "task timed out"
	}
	res.TaskId = task.Id
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// execTask запускает процесс через оболочку и собирает stdout/stderr/exit code.
func execTask(ctx context.Context, t *pb.ExecTask) *pb.TaskResult {
	name, args := shell()
	cmd := exec.CommandContext(ctx, name, append(args, t.Cmd)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	res := &pb.TaskResult{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		ExitCode:  int32(cmd.ProcessState.ExitCode()),
	}
	if runErr != nil {
		res.Status = pb.TaskResult_STATUS_ERROR
		res.Error = runErr.Error()
	} else {
		res.Status = pb.TaskResult_STATUS_OK
	}
	return res
}

// readTask читает файл, ограничивая размер ответа max_bytes.
func readTask(ctx context.Context, t *pb.ReadFileRequest) *pb.TaskResult {
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return errResult(err)
	}
	if t.MaxBytes > 0 && int64(len(data)) > t.MaxBytes {
		data = data[:t.MaxBytes]
	}
	return &pb.TaskResult{
		Status: pb.TaskResult_STATUS_OK,
		Stdout: data,
	}
}

// writeTask записывает файл; при create_dirs создаёт родительские каталоги.
func writeTask(ctx context.Context, t *pb.WriteFileRequest) *pb.TaskResult {
	if t.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(t.Path), 0o755); err != nil {
			return errResult(err)
		}
	}
	if err := os.WriteFile(t.Path, t.Content, 0o644); err != nil {
		return errResult(err)
	}
	return &pb.TaskResult{Status: pb.TaskResult_STATUS_OK}
}

// errResult собирает результат с ошибкой.
func errResult(err error) *pb.TaskResult {
	return &pb.TaskResult{
		Status: pb.TaskResult_STATUS_ERROR,
		Error:  err.Error(),
	}
}

// shell возвращает команду оболочки для запуска cmd.
func shell() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C"}
	}
	return "sh", []string{"-c"}
}

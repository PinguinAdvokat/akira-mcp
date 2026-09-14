package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// writeFileT — вспомогательный WriteFile-таск.
func writeFileT(t *testing.T, path, content string) *pb.TaskResult {
	t.Helper()
	return Execute(&pb.Task{Payload: &pb.Task_WriteFile{WriteFile: &pb.WriteFileRequest{
		Path: path, Content: []byte(content), CreateDirs: true,
	}}})
}

// makeLines собирает файл из n строк вида "line1".."lineN" (с финальным '\n').
func makeLines(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		b.WriteString("line")
		b.WriteString(strings.TrimSpace(itoa(i)))
		b.WriteByte('\n')
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestReadTaskWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	if res := writeFileT(t, path, makeLines(100)); res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("setup write: %s", res.Error)
	}

	tests := []struct {
		name      string
		offset    int64
		limit     int64
		maxBytes  int64
		wantLines string // ожидаемое содержимое stdout
		wantTotal int64
		wantTrunc bool
	}{
		{"full", 0, 0, 0, makeLines(100), 100, false},
		{"window", 10, 5, 0, "line10\nline11\nline12\nline13\nline14\n", 100, false},
		{"from_one", 1, 2, 0, "line1\nline2\n", 100, false},
		{"limit_zero_offset_set", 50, 0, 0, makeLines(100)[len(makeLines(49)):], 100, false},
		{"beyond_eof", 999, 5, 0, "", 100, false},
		{"max_bytes_cut", 1, 10, 10, "line1\nline", 100, true},
		{"max_bytes_exact_lines", 1, 2, 12, "line1\nline2\n", 100, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Execute(&pb.Task{Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{
				Path: path, Offset: tt.offset, Limit: tt.limit, MaxBytes: tt.maxBytes,
			}}})
			if res.Status != pb.TaskResult_STATUS_OK {
				t.Fatalf("status = %s, error = %s", res.Status, res.Error)
			}
			if string(res.Stdout) != tt.wantLines {
				t.Errorf("stdout = %q, want %q", res.Stdout, tt.wantLines)
			}
			if res.TotalLines != tt.wantTotal {
				t.Errorf("total_lines = %d, want %d", res.TotalLines, tt.wantTotal)
			}
			if res.Truncated != tt.wantTrunc {
				t.Errorf("truncated = %v, want %v", res.Truncated, tt.wantTrunc)
			}
		})
	}
}

func TestReadTaskEdgeCases(t *testing.T) {
	dir := t.TempDir()

	t.Run("no_trailing_newline", func(t *testing.T) {
		p := filepath.Join(dir, "nonl.txt")
		if res := writeFileT(t, p, "a\nb\nc"); res.Status != pb.TaskResult_STATUS_OK {
			t.Fatal(res.Error)
		}
		res := Execute(&pb.Task{Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{Path: p, Offset: 3, Limit: 1}}})
		if string(res.Stdout) != "c" {
			t.Errorf("stdout = %q, want %q", res.Stdout, "c")
		}
		if res.TotalLines != 3 {
			t.Errorf("total = %d, want 3", res.TotalLines)
		}
	})

	t.Run("long_line_over_64k", func(t *testing.T) {
		p := filepath.Join(dir, "long.txt")
		long := strings.Repeat("x", 100_000)
		if res := writeFileT(t, p, long+"\n"); res.Status != pb.TaskResult_STATUS_OK {
			t.Fatal(res.Error)
		}
		res := Execute(&pb.Task{Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{Path: p}}})
		if len(res.Stdout) != 100_001 {
			t.Errorf("len(stdout) = %d, want 100001", len(res.Stdout))
		}
	})

	t.Run("empty_file", func(t *testing.T) {
		p := filepath.Join(dir, "empty.txt")
		if res := writeFileT(t, p, ""); res.Status != pb.TaskResult_STATUS_OK {
			t.Fatal(res.Error)
		}
		res := Execute(&pb.Task{Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{Path: p}}})
		if len(res.Stdout) != 0 || res.TotalLines != 0 {
			t.Errorf("stdout = %q, total = %d; want empty, 0", res.Stdout, res.TotalLines)
		}
	})

	t.Run("missing_file", func(t *testing.T) {
		res := Execute(&pb.Task{Payload: &pb.Task_ReadFile{ReadFile: &pb.ReadFileRequest{Path: filepath.Join(dir, "nope")}}})
		if res.Status != pb.TaskResult_STATUS_ERROR {
			t.Errorf("status = %s, want STATUS_ERROR", res.Status)
		}
	})
}

func TestEditTask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edit.txt")
	writeFileT(t, path, "alpha\nbeta\ngamma\nbeta\n")

	edit := func(old, new string, all bool) *pb.TaskResult {
		return Execute(&pb.Task{Payload: &pb.Task_EditFile{EditFile: &pb.EditFileRequest{
			Path: path, OldStr: old, NewStr: new, ReplaceAll: all,
		}}})
	}

	t.Run("not_found", func(t *testing.T) {
		res := edit("missing", "x", false)
		if res.Status != pb.TaskResult_STATUS_ERROR || !strings.Contains(res.Error, "old_str not found") {
			t.Errorf("status = %s, error = %q", res.Status, res.Error)
		}
	})

	t.Run("ambiguous", func(t *testing.T) {
		res := edit("beta", "x", false)
		if res.Status != pb.TaskResult_STATUS_ERROR || !strings.Contains(res.Error, "found 2 times") {
			t.Errorf("status = %s, error = %q", res.Status, res.Error)
		}
	})

	t.Run("replace_all", func(t *testing.T) {
		res := edit("beta", "BETA", true)
		if res.Status != pb.TaskResult_STATUS_OK {
			t.Fatalf("status = %s, error = %q", res.Status, res.Error)
		}
		data, _ := os.ReadFile(path)
		if want := "alpha\nBETA\ngamma\nBETA\n"; string(data) != want {
			t.Errorf("content = %q, want %q", data, want)
		}
		if !strings.Contains(string(res.Stdout), "replaced 2 occurrence(s)") {
			t.Errorf("stdout = %q", res.Stdout)
		}
	})

	t.Run("single", func(t *testing.T) {
		res := edit("gamma", "GAMMA", false)
		if res.Status != pb.TaskResult_STATUS_OK {
			t.Fatalf("status = %s, error = %q", res.Status, res.Error)
		}
		data, _ := os.ReadFile(path)
		if !bytes.Contains(data, []byte("GAMMA")) {
			t.Errorf("content = %q, missing GAMMA", data)
		}
	})

	t.Run("empty_old_str", func(t *testing.T) {
		res := edit("", "x", false)
		if res.Status != pb.TaskResult_STATUS_ERROR {
			t.Errorf("status = %s, want STATUS_ERROR", res.Status)
		}
	})

	t.Run("same_strings", func(t *testing.T) {
		res := edit("alpha", "alpha", false)
		if res.Status != pb.TaskResult_STATUS_ERROR {
			t.Errorf("status = %s, want STATUS_ERROR", res.Status)
		}
	})

	t.Run("perm_preserved", func(t *testing.T) {
		p := filepath.Join(dir, "perm.txt")
		writeFileT(t, p, "secret\n")
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		res := Execute(&pb.Task{Payload: &pb.Task_EditFile{EditFile: &pb.EditFileRequest{
			Path: p, OldStr: "secret", NewStr: "open",
		}}})
		if res.Status != pb.TaskResult_STATUS_OK {
			t.Fatalf("status = %s, error = %q", res.Status, res.Error)
		}
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("perm = %v, want -rw-------", st.Mode().Perm())
		}
	})
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		rel     string
		want    bool
	}{
		{"**/*.go", "main.go", true},
		{"**/*.go", "a/b/c.go", true},
		{"**/*.go", "a/b/c.txt", false},
		{"*.go", "main.go", true},
		{"*.go", "a/main.go", false}, // '*' не пересекает '/'
		{"a/*/c.go", "a/b/c.go", true},
		{"a/*/c.go", "a/b/d/c.go", false},
		{"**", "anything/at/all", true},
		{"**/x", "x", true}, // '**' может съесть ноль сегментов
		{"**/x", "a/b/x", true},
		{"?.txt", "a.txt", true},
		{"?.txt", "ab.txt", false},
		{"[a-c].txt", "b.txt", true},
		{"[a-c].txt", "d.txt", false},
		{"a/**", "a", true}, // '**' может съесть ноль сегментов (как и '**/x' → 'x')
		{"a/**", "a/b", true},
		{"a/**", "a/b/c", true},
	}
	for _, tt := range tests {
		if got := matchGlob(tt.pattern, tt.rel); got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.rel, got, tt.want)
		}
	}
}

func TestGlobTask(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"x.go", "a/b/c.go", "a/d.txt", "a/e/f.go"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if res := writeFileT(t, full, "x"); res.Status != pb.TaskResult_STATUS_OK {
			t.Fatal(res.Error)
		}
	}

	res := Execute(&pb.Task{Payload: &pb.Task_Glob{Glob: &pb.GlobRequest{Path: dir, Pattern: "**/*.go"}}})
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatalf("status = %s, error = %q", res.Status, res.Error)
	}
	got := strings.Split(string(res.Stdout), "\n")
	want := []string{
		filepath.Join(dir, "a", "b", "c.go"),
		filepath.Join(dir, "a", "e", "f.go"),
		filepath.Join(dir, "x.go"),
	}
	if len(got) != len(want) {
		t.Fatalf("matches = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("match[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if res.TotalLines != 3 || res.Truncated {
		t.Errorf("total = %d, truncated = %v; want 3, false", res.TotalLines, res.Truncated)
	}

	t.Run("missing_base", func(t *testing.T) {
		res := Execute(&pb.Task{Payload: &pb.Task_Glob{Glob: &pb.GlobRequest{Path: filepath.Join(dir, "nope"), Pattern: "**"}}})
		if res.Status != pb.TaskResult_STATUS_ERROR {
			t.Errorf("status = %s, want STATUS_ERROR", res.Status)
		}
	})

	t.Run("cap", func(t *testing.T) {
		sub := t.TempDir()
		for i := 0; i < maxGlobResults+1; i++ {
			writeFileT(t, filepath.Join(sub, "f"+itoa(i)+".txt"), "x")
		}
		res := Execute(&pb.Task{Payload: &pb.Task_Glob{Glob: &pb.GlobRequest{Path: sub, Pattern: "*.txt"}}})
		if res.Status != pb.TaskResult_STATUS_OK {
			t.Fatalf("status = %s", res.Status)
		}
		if !res.Truncated {
			t.Error("truncated = false, want true")
		}
		if res.TotalLines != maxGlobResults+1 {
			t.Errorf("total = %d, want %d", res.TotalLines, maxGlobResults+1)
		}
		if n := strings.Count(string(res.Stdout), "\n") + 1; n != maxGlobResults {
			t.Errorf("returned %d matches, want %d", n, maxGlobResults)
		}
	})
}

func TestListTask(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"top.txt", "sub/inner.txt", "sub/deep/x.txt", "sub2/y.txt"} {
		writeFileT(t, filepath.Join(dir, filepath.FromSlash(p)), "x")
	}

	tests := []struct {
		depth int32
		want  string
	}{
		{1, "sub/\nsub2/\ntop.txt"},
		{2, "sub/\nsub/deep/\nsub/inner.txt\nsub2/\nsub2/y.txt\ntop.txt"},
		{3, "sub/\nsub/deep/\nsub/deep/x.txt\nsub/inner.txt\nsub2/\nsub2/y.txt\ntop.txt"},
	}
	for _, tt := range tests {
		res := Execute(&pb.Task{Payload: &pb.Task_List{List: &pb.ListRequest{Path: dir, Depth: tt.depth}}})
		if res.Status != pb.TaskResult_STATUS_OK {
			t.Fatalf("depth %d: status = %s, error = %q", tt.depth, res.Status, res.Error)
		}
		if string(res.Stdout) != tt.want {
			t.Errorf("depth %d: stdout = %q, want %q", tt.depth, res.Stdout, tt.want)
		}
	}

	t.Run("missing_dir", func(t *testing.T) {
		res := Execute(&pb.Task{Payload: &pb.Task_List{List: &pb.ListRequest{Path: filepath.Join(dir, "nope")}}})
		if res.Status != pb.TaskResult_STATUS_ERROR {
			t.Errorf("status = %s, want STATUS_ERROR", res.Status)
		}
	})
}

func TestWriteTaskPermPreserved(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.txt")
	writeFileT(t, p, "old")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	res := writeFileT(t, p, "new")
	if res.Status != pb.TaskResult_STATUS_OK {
		t.Fatal(res.Error)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v, want -rw-------", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content = %q", b)
	}
}

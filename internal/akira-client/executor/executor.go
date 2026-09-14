// Package executor исполняет задачи, полученные от сервера.
package executor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	pb "github.com/PinguinAdvokat/akira-mcp/pkg/api/connectionpb/v1"
)

// Ограничения ответов glob/list, чтобы не раздувать TaskResult.
const (
	maxGlobResults = 1000
	maxListEntries = 1000
)

// maxGlobPatterns ограничивает число шаблонов после разворота фигурных
// скобок, чтобы вложенные группы вида {a,b}{a,b}{a,b}… не разрослись
// до астрономического количества вариантов.
const maxGlobPatterns = 1000

var errTooManyGlobPatterns = fmt.Errorf("glob pattern expands to more than %d variants", maxGlobPatterns)

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
	case *pb.Task_EditFile:
		res = editTask(ctx, payload.EditFile)
	case *pb.Task_Glob:
		res = globTask(ctx, payload.Glob)
	case *pb.Task_List:
		res = listTask(ctx, payload.List)
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
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: int32(cmd.ProcessState.ExitCode()),
	}
	if runErr != nil {
		res.Status = pb.TaskResult_STATUS_ERROR
		res.Error = runErr.Error()
	} else {
		res.Status = pb.TaskResult_STATUS_OK
	}
	return res
}

// readTask читает окно строк файла [offset, offset+limit), не загружая
// весь файл в память, и считает общее число строк в файле (total_lines).
// max_bytes применяется к окну ответа: строка, не влезающая целиком,
// обрезается по байтам и выставляет truncated. CRLF сохраняется как есть.
func readTask(ctx context.Context, t *pb.ReadFileRequest) *pb.TaskResult {
	f, err := os.Open(t.Path)
	if err != nil {
		return errResult(err)
	}
	defer f.Close()

	offset := max(t.Offset, 1) // 0 → 1
	r := bufio.NewReader(f)
	var out bytes.Buffer // окно ответа
	var lines int64      // строк в окне
	var total int64      // всего строк в файле
	truncated := false

	for {
		line, err := r.ReadString('\n') // сохраняет '\n'; io.EOF — последняя строка без '\n'
		if len(line) > 0 {
			total++
			if total >= offset && (t.Limit <= 0 || lines < t.Limit) {
				if t.MaxBytes > 0 && int64(out.Len()+len(line)) > t.MaxBytes {
					// влезает частично — отрезаем по байтам
					if room := int(t.MaxBytes) - out.Len(); room > 0 {
						out.WriteString(line[:room])
					}
					truncated = true
				} else {
					out.WriteString(line)
					lines++
				}
			}
		}
		if err != nil {
			break // io.EOF
		}
		if ctx.Err() != nil {
			return errResult(ctx.Err())
		}
	}
	return &pb.TaskResult{
		Status:     pb.TaskResult_STATUS_OK,
		Stdout:     out.Bytes(),
		TotalLines: total,
		Truncated:  truncated,
	}
}

// writeTask записывает файл; при create_dirs создаёт родительские
// каталоги. Существующий файл сохраняет свои права, новый — 0644.
func writeTask(ctx context.Context, t *pb.WriteFileRequest) *pb.TaskResult {
	if t.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(t.Path), 0o755); err != nil {
			return errResult(err)
		}
	}
	if err := os.WriteFile(t.Path, t.Content, filePerm(t.Path)); err != nil {
		return errResult(err)
	}
	return &pb.TaskResult{Status: pb.TaskResult_STATUS_OK}
}

// editTask заменяет old_str → new_str с семантикой Claude Code Edit:
// без replace_all строка old_str обязана встречаться ровно один раз.
// Права существующего файла сохраняются.
func editTask(ctx context.Context, t *pb.EditFileRequest) *pb.TaskResult {
	if t.OldStr == "" {
		return errResult(errors.New("old_str must not be empty"))
	}
	if t.OldStr == t.NewStr {
		return errResult(errors.New("new_str must differ from old_str"))
	}
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return errResult(err)
	}

	n := bytes.Count(data, []byte(t.OldStr))
	switch {
	case n == 0:
		return errResult(fmt.Errorf("old_str not found in %s", t.Path))
	case n > 1 && !t.ReplaceAll:
		return errResult(fmt.Errorf("old_str found %d times in %s; pass replace_all to replace every occurrence", n, t.Path))
	}

	var repl []byte
	if t.ReplaceAll {
		repl = bytes.ReplaceAll(data, []byte(t.OldStr), []byte(t.NewStr))
	} else {
		repl = bytes.Replace(data, []byte(t.OldStr), []byte(t.NewStr), 1)
	}
	if err := os.WriteFile(t.Path, repl, filePerm(t.Path)); err != nil {
		return errResult(err)
	}
	if !t.ReplaceAll {
		n = 1
	}
	return &pb.TaskResult{
		Status: pb.TaskResult_STATUS_OK,
		Stdout: []byte(fmt.Sprintf("replaced %d occurrence(s)", n)),
	}
}

// globTask ищет файлы по шаблону pattern относительно каталога path.
// Шаблон сначала проходит brace expansion ("*.{go,md}" → "*.go",
// "*.md") — сопоставляется любое из полученных выражений. stdout —
// абсолютные пути совпадений через '\n', отсортированные
// (WalkDir обходит лексикографически); total_lines — всего совпадений
// до ограничения, truncated — ответ обрезан лимитом.
func globTask(ctx context.Context, t *pb.GlobRequest) *pb.TaskResult {
	patterns, err := expandBraces(strings.TrimPrefix(strings.TrimPrefix(t.Pattern, "/"), "./"))
	if err != nil {
		return errResult(err)
	}
	var matches []string
	total := 0
	err = filepath.WalkDir(t.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err // несуществующий базовый каталог — ошибка задачи
		}
		rel, relErr := filepath.Rel(t.Path, p)
		if relErr != nil || rel == "." {
			return nil
		}
		if matchAnyGlob(patterns, filepath.ToSlash(rel)) {
			total++
			if len(matches) < maxGlobResults {
				matches = append(matches, p)
			}
		}
		return nil
	})
	if err != nil {
		return errResult(err)
	}
	return &pb.TaskResult{
		Status:     pb.TaskResult_STATUS_OK,
		Stdout:     []byte(strings.Join(matches, "\n")),
		TotalLines: int64(total),
		Truncated:  total > len(matches),
	}
}

// listTask собирает листинг каталога path до глубины depth: по строке
// на запись, путь относительно t.Path, каталоги с суффиксом '/'.
func listTask(ctx context.Context, t *pb.ListRequest) *pb.TaskResult {
	depth := max(int(t.Depth), 1)
	var out []string
	total := 0
	err := filepath.WalkDir(t.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(t.Path, p)
		if relErr != nil || rel == "." {
			return nil
		}
		if strings.Count(filepath.ToSlash(rel), "/")+1 > depth {
			if d.IsDir() {
				return fs.SkipDir // глубже не спускаемся
			}
			return nil
		}
		total++
		if len(out) < maxListEntries {
			entry := filepath.ToSlash(rel)
			if d.IsDir() {
				entry += "/"
			}
			out = append(out, entry)
		}
		return nil
	})
	if err != nil {
		return errResult(err)
	}
	return &pb.TaskResult{
		Status:     pb.TaskResult_STATUS_OK,
		Stdout:     []byte(strings.Join(out, "\n")),
		TotalLines: int64(total),
		Truncated:  total > len(out),
	}
}

// matchAnyGlob проверяет rel против любого из шаблонов — после
// разворота фигурных скобок их может быть несколько.
func matchAnyGlob(patterns []string, rel string) bool {
	for _, p := range patterns {
		if matchGlob(p, rel) {
			return true
		}
	}
	return false
}

// matchGlob сопоставляет относительный путь со шаблоном по сегментам
// через '/'. "**" соответствует любому числу сегментов (включая ноль),
// остальные сегменты сверяются path.Match по одному сегменту (поэтому
// '*' не пересекает '/'). Фигурные скобки разворачиваются раньше,
// на уровне globTask. Замечание: литеральный '\' в POSIX-имени
// файла требует экранирования в шаблоне.
func matchGlob(pattern, rel string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

// expandBraces разворачивает bash-подобные фигурные скобки в шаблоне:
// альтернативы через запятую ("*.{go,md}" → "*.go", "*.md"), диапазоны
// ("{1..3}", "{a..z}", включая убывающие) и вложенность
// ("a{b,{c,d}}e" → "abe", "ace", "ade"). Семантика как в bash:
// группа без запятой и без диапазона ("a{b}c"), как и непарная '{',
// остаётся литералом, но её содержимое сканируется дальше
// ("{a{b,c}}" → "{ab}", "{ac}"); '\{' экранируется. Возвращает
// errTooManyGlobPatterns, если вариантов больше maxGlobPatterns.
func expandBraces(pattern string) ([]string, error) {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++ // экранированный символ пропускаем вместе с ним
		case '{':
			end := closingBrace(pattern, i)
			if end < 0 {
				continue // непарная '{' — литерал; ищем следующую группу после неё
			}
			alts, err := braceAlts(pattern[i+1 : end])
			if err != nil {
				return nil, err
			}
			if alts == nil {
				continue // не разворачивается — литеральная группа; внутри может быть разворачиваемая
			}
			var out []string
			for _, alt := range alts {
				// хвост с оставшимися группами приписываем к каждой альтернативе
				// и разворачиваем рекурсивно
				tails, err := expandBraces(alt + pattern[end+1:])
				if err != nil {
					return nil, err
				}
				for _, tail := range tails {
					out = append(out, pattern[:i]+tail)
				}
			}
			if len(out) > maxGlobPatterns {
				return nil, errTooManyGlobPatterns
			}
			return out, nil
		}
	}
	return []string{pattern}, nil
}

// closingBrace возвращает индекс парной '}' для pattern[open] == '{'
// с учётом вложенности и экранирования, либо -1.
func closingBrace(pattern string, open int) int {
	depth := 0
	for i := open; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// braceAlts возвращает альтернативы содержимого группы — разбиение по
// запятым верхнего уровня ('\,' не считается) — либо элементы
// диапазона {lo..hi}. nil — группа не разворачивается (без запятой и
// не диапазон); диапазон шире maxGlobPatterns — errTooManyGlobPatterns.
func braceAlts(inner string) ([]string, error) {
	var alts []string
	depth, last := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '\\':
			i++
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				alts = append(alts, inner[last:i])
				last = i + 1
			}
		}
	}
	alts = append(alts, inner[last:])
	if len(alts) > 1 {
		return alts, nil
	}
	return braceRange(inner)
}

// braceRange разворачивает диапазон {lo..hi}: посимвольный ("a..z")
// или числовой ("1..5", допускаются отрицательные), убывающий —
// в обратном порядке. nil — содержимое не является диапазоном.
func braceRange(inner string) ([]string, error) {
	lo, hi, ok := strings.Cut(inner, "..")
	if !ok {
		return nil, nil
	}
	var from, to int
	switch {
	case len(lo) == 1 && len(hi) == 1:
		from, to = int(lo[0]), int(hi[0])
	default:
		nlo, errLo := strconv.Atoi(lo)
		nhi, errHi := strconv.Atoi(hi)
		if errLo != nil || errHi != nil {
			return nil, nil
		}
		from, to = nlo, nhi
	}
	asc := from <= to
	if !asc {
		from, to = to, from
	}
	if to-from+1 > maxGlobPatterns {
		return nil, errTooManyGlobPatterns
	}
	alts := make([]string, 0, to-from+1)
	for n := from; n <= to; n++ {
		if len(lo) == 1 && len(hi) == 1 {
			alts = append(alts, string(rune(n)))
		} else {
			alts = append(alts, strconv.Itoa(n))
		}
	}
	if !asc {
		for i, j := 0, len(alts)-1; i < j; i, j = i+1, j-1 {
			alts[i], alts[j] = alts[j], alts[i]
		}
	}
	return alts, nil
}

// matchSegments рекурсивно сопоставляет сегменты шаблона и пути.
func matchSegments(pat, seg []string) bool {
	for len(pat) > 0 {
		switch {
		case pat[0] == "**":
			// '**' съедает 0..len(seg) сегментов
			for i := 0; i <= len(seg); i++ {
				if matchSegments(pat[1:], seg[i:]) {
					return true
				}
			}
			return false
		case len(seg) == 0:
			return false
		default:
			ok, err := path.Match(pat[0], seg[0])
			if err != nil || !ok {
				return false
			}
			pat, seg = pat[1:], seg[1:]
		}
	}
	return len(seg) == 0
}

// filePerm возвращает права для записи: права существующего файла
// (чтобы edit/write не сбрасывали их) либо 0644 для нового.
func filePerm(p string) os.FileMode {
	if st, err := os.Stat(p); err == nil {
		return st.Mode().Perm()
	}
	return 0o644
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

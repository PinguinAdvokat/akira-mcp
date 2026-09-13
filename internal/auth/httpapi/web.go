// Файл web.go — раздача встроенного фронтенда auth-сервиса.
//
// Фронтенд (каталог web/) — одностраничное приложение без сборки
// (ванильный JS), зашитое в бинарник через go:embed. Живёт в auth-
// сервисе: GET / отдаёт index.html, GET /assets/* — статику.
// OAuth-флоу для MCP-хостов использует его же: /authorize
// редиректит сюда с исходными query-параметрами, форма логина
// отправляет их в POST /authorize/confirm.
//
// Раздача предельно простая: три файла, иммутабные имена
// (index.html, app.js, styles.css), поэтому без хешей и версионирования
// — короткое кеширование с must-revalidate, чтобы обновление
// фронтенда подхватывалось после рестарта сервиса.

package authhttp

import (
	"embed"
	"net/http"
	"strings"
)

// webFS — файлы фронтенда, зашитые в бинарник.
//
//go:embed web/index.html web/assets/app.js web/assets/styles.css
var webFS embed.FS

// knownAssets — статические ассеты фронтенда. Набор фиксированный,
// карта вместо http.FileServer: без листинга каталога и без
// обработки произвольных путей (никакого path traversal).
var knownAssets = map[string]string{
	"app.js":     "web/assets/app.js",
	"styles.css": "web/assets/styles.css",
}

// handleIndex отдаёт index.html — точку входа SPA.
func (h *handler) handleIndex(w http.ResponseWriter, _ *http.Request) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		// go:embed гарантирует наличие файла — это внутренняя ошибка.
		h.logger.Error("read embedded index.html", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "frontend is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// CSP закрывает внешние скрипты/стили (SPA без сборки — всё своё),
	// данные — только data:-иконка; токены в localStorage — потому
	// важна нулевая XSS-поверхность (см. app.js: только textContent).
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; "+
			"connect-src 'self'; img-src 'self' data:; form-action 'self'; "+
			"base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		h.logger.Error("write index.html", "err", err)
	}
}

// handleAsset отдаёт статический ассет фронтенда по имени файла.
// Метод уже сматчен маршрутом /assets/{name}, здесь — только
// проверка по белому списку.
func (h *handler) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/assets/")
	path, ok := knownAssets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile(path)
	if err != nil {
		h.logger.Error("read embedded asset", "path", path, "err", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		h.logger.Error("write asset", "path", path, "err", err)
	}
}

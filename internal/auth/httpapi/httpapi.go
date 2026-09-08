// Пакет authhttp — HTTP-слой auth-сервиса: регистрация с подтверждением
// email коротким кодом из письма (код вводится вместе с email —
// верификация сразу выдаёт пару токенов, без отдельного логина),
// выдача пар токенов (password / refresh_token grants), ротация
// и отзыв refresh-токенов, данные аккаунта и перегенерация
// connect_key, публикация JWKS. JSON в формате, близком к OAuth2.
//
// TLS-терминация и ограничение частоты запросов — на обратном
// прокси (nginx) перед сервисом; сам сервис слушает открытый HTTP.
package authhttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	authmail "github.com/PinguinAdvokat/akira-mcp/internal/auth/mail"
	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
	authtoken "github.com/PinguinAdvokat/akira-mcp/internal/auth/token"
)

// connectKeyAttempts — предел попыток генерации connect_key при
// коллизии (ключи 22-символьные, вероятность коллизии исчезающе мала,
// попыток с запасом).
const connectKeyAttempts = 8

// VerificationCodeLen — длина кода подтверждения email (цифры).
const VerificationCodeLen = 6

// maxBodyBytes — потолок размера JSON-тела запроса: без него тело
// неограниченного размера читается в память целиком.
const maxBodyBytes = 1 << 20 // 1 MiB

// dummyHash — bcrypt-хеш для сравнения при неизвестном пользователе:
// сравнение выполняется всегда, чтобы время ответа не выдавало,
// существует ли имя.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("akira-dummy-password"), bcrypt.DefaultCost)

// Config — параметры HTTP-слоя, не сводимые к стору и токенам.
type Config struct {
	// Mail — отправитель писем с кодом подтверждения.
	Mail authmail.Sender
	// EmailTTL — срок жизни кода подтверждения email.
	EmailTTL time.Duration
}

// handler — состояние HTTP-слоя auth-сервиса.
type handler struct {
	tokens *authtoken.Manager
	store  authstore.Store
	cfg    Config
	logger *slog.Logger
}

// New собирает http.Handler auth-сервиса.
func New(tokens *authtoken.Manager, store authstore.Store, cfg Config) http.Handler {
	h := &handler{
		tokens: tokens,
		store:  store,
		cfg:    cfg,
		logger: slog.Default().With(slog.String("component", "authHTTP")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /verify", h.handleVerify)
	mux.HandleFunc("POST /verify/resend", h.handleResend)
	mux.HandleFunc("POST /token", h.handleToken)
	mux.HandleFunc("POST /revoke", h.handleRevoke)
	mux.HandleFunc("GET /me", h.handleMe)
	mux.HandleFunc("POST /connect-key/regenerate", h.handleRegenerateConnectKey)
	mux.HandleFunc("GET /jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	return mux
}

// tokenRequest — тело POST /token.
type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	RefreshToken string `json:"refresh_token"`
}

// tokenResponse — успешный ответ POST /token.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// errorResponse — OAuth2-стиль: {"error":"<код>","error_description":"…"}.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// decodeJSON читает и разбирает JSON-тело запроса с потолком
// maxBodyBytes. Ответ при ошибке пишет сам (400 — битый JSON,
// 413 — превышен лимит) и возвращает false, если обработку
// продолжать нельзя.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(body).Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	return true
}

func (h *handler) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	switch req.GrantType {
	case "password":
		h.grantPassword(w, r.Context(), req)
	case "refresh_token":
		h.grantRefresh(w, r.Context(), req)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be password or refresh_token")
	}
}

// grantPassword проверяет учётные данные и выдаёт новую пару токенов.
// Неподтверждённый email и неизвестное имя — тот же ответ и то же время
// работы, что и при неверном пароле (анти-энумерация): bcrypt-сравнение
// выполняется всегда, и до него проверяется пароль, а не верификация.
func (h *handler) grantPassword(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	user, err := h.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			// Сбой стора — не «неверные учётные данные»: наружу 500.
			h.logger.Error("password grant: lookup user", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
			return
		}
		// Неизвестное имя: то же bcrypt-сравнение, чтобы время ответа
		// не выдавало существование учётной записи.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		h.logger.Warn("password grant failed", "username", req.Username)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}
	if bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)) != nil || !user.EmailVerified {
		h.logger.Warn("password grant failed", "username", req.Username, "verified", user.EmailVerified)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "invalid credentials")
		return
	}

	h.issuePair(w, ctx, user.ID, user.Username)
}

// grantRefresh заменяет refresh-токен новым (одноразовость: ротация)
// и выдаёт новую пару. Неизвестный, истёкший или уже использованный
// токен — invalid_grant; сбой хранилища — server_error, при этом
// старый токен не сжигается (ротация атомарна).
func (h *handler) grantRefresh(w http.ResponseWriter, ctx context.Context, req tokenRequest) {
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Ротация атомарна: потребление старого токена и сохранение нового —
	// одна операция стора. Раньше consume и save были раздельными, и
	// транзиентный сбой между ними уничтожал сессию. Подпись access —
	// уже поверх состоявшейся ротации (это чистая криптография в памяти,
	// она не падает от состояния БД).
	refreshRaw, refreshHash, err := h.tokens.NewRefreshToken()
	if err != nil {
		h.logger.Error("generate refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}
	now := time.Now()
	rec, err := h.store.RotateRefresh(ctx, hashToken(req.RefreshToken), authstore.RefreshToken{
		TokenHash: refreshHash,
		ExpiresAt: now.Add(h.tokens.RefreshTTL()),
		CreatedAt: now,
	})
	if err != nil {
		if errors.Is(err, authstore.ErrRefreshNotFound) {
			h.logger.Warn("refresh grant failed", "reason", "unknown, expired or already used token")
			writeError(w, http.StatusUnauthorized, "invalid_grant", "unknown, expired or already used refresh token")
			return
		}
		h.logger.Error("rotate refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	access, err := h.tokens.NewAccessToken(rec.UserID)
	if err != nil {
		h.logger.Error("sign access token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}

	h.logger.Info("tokens issued", "user_id", rec.UserID, "grant", "refresh_token")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.tokens.AccessTTL().Seconds()),
		RefreshToken: refreshRaw,
	})
}

// issuePair выпускает access + refresh и сохраняет хеш refresh в стор.
// Используется там, где старого refresh-токена нет (логин и верификация);
// ротация существующего — grantRefresh через RotateRefresh.
func (h *handler) issuePair(w http.ResponseWriter, ctx context.Context, userID, username string) {
	access, err := h.tokens.NewAccessToken(userID)
	if err != nil {
		h.logger.Error("sign access token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}
	refreshRaw, refreshHash, err := h.tokens.NewRefreshToken()
	if err != nil {
		h.logger.Error("generate refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}

	now := time.Now()
	if err := h.store.SaveRefresh(ctx, authstore.RefreshToken{
		TokenHash: refreshHash,
		UserID:    userID,
		ExpiresAt: now.Add(h.tokens.RefreshTTL()),
		CreatedAt: now,
	}); err != nil {
		h.logger.Error("save refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue tokens")
		return
	}

	h.logger.Info("tokens issued", "user_id", userID, "username", username)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.tokens.AccessTTL().Seconds()),
		RefreshToken: refreshRaw,
	})
}

// handleRegister создаёт пользователя с неподтверждённым email
// и отправляет письмо с кодом верификации.
func (h *handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Username == "" || req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and a valid email are required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "invalid_request", "password must be at least 8 characters")
		return
	}
	// bcrypt использует только первые 72 байта пароля; длиннее — ошибка
	// на этапе хеширования, поэтому режем сразу с понятным ответом.
	if len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "invalid_request", "password must be at most 72 bytes")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("hash password", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}

	// Пользователь и первый код подтверждения создаются атомарно
	// (CreateUserWithCode): сбой не оставляет пользователя без кода,
	// которому немедленно нужен resend.
	code := generateVerificationCode()
	now := time.Now()
	user, err := h.store.CreateUserWithCode(r.Context(), req.Username, req.Email, hash,
		hashToken(code), now.Add(h.cfg.EmailTTL))
	if err != nil {
		switch {
		case errors.Is(err, authstore.ErrUserExists):
			writeError(w, http.StatusConflict, "user_exists", "username is already taken")
		case errors.Is(err, authstore.ErrEmailExists):
			writeError(w, http.StatusConflict, "email_exists", "email is already registered")
		default:
			h.logger.Error("create user", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		}
		return
	}

	if err := h.cfg.Mail.SendCode(r.Context(), user.Email, code, h.cfg.EmailTTL.String()); err != nil {
		h.logger.Error("send verification code", "user_id", user.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to send verification code")
		return
	}

	h.logger.Info("user registered, verification code sent", "user_id", user.ID, "username", user.Username)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "pending_verification"})
}

// handleVerify сверяет код подтверждения (email + код из письма),
// помечает email проверенным и сразу выдаёт пару токенов —
// пользователю не нужно логиниться после верификации. Сверка кода,
// пометка email и назначение connect_key — один атомарный вызов стора
// (CompleteEmailVerification): сбой любого шага не сжигает код.
// connect_key в ответ не входит: фронтенд получает его через GET /me.
func (h *handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email and code are required")
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			h.logger.Error("verify: lookup user", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "verification failed")
			return
		}
		// Одинаковый ответ для неизвестного email и неверного кода —
		// против перечисления адресов.
		h.logger.Warn("verify failed", "reason", "unknown email")
		writeError(w, http.StatusUnauthorized, "invalid_code", "wrong or expired verification code")
		return
	}

	// Коллизии connect_key практически невозможны (109 бит энтропии),
	// но при ErrConnectKeyExists код не потребляется — просто повторяем
	// с другим ключом.
	key, err := authstore.GenerateConnectKey()
	if err != nil {
		h.logger.Error("generate connect key", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "verification failed")
		return
	}
	for attempt := 0; attempt < connectKeyAttempts; attempt++ {
		err = h.store.CompleteEmailVerification(r.Context(), user.ID, hashToken(req.Code), key)
		if errors.Is(err, authstore.ErrConnectKeyExists) {
			if key, err = authstore.GenerateConnectKey(); err != nil {
				break
			}
			continue
		}
		break
	}
	if err != nil {
		switch {
		case errors.Is(err, authstore.ErrVerificationNotFound),
			errors.Is(err, authstore.ErrVerificationWrongCode):
			// Причины отказа не различаем наружу: неверный код, истёкший,
			// исчерпаны попытки, уже потреблён — одно и то же.
			h.logger.Warn("verify failed", "user_id", user.ID, "err", err)
			writeError(w, http.StatusUnauthorized, "invalid_code", "wrong or expired verification code")
		default:
			h.logger.Error("complete email verification", "user_id", user.ID, "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "verification failed")
		}
		return
	}

	h.logger.Info("email verified", "user_id", user.ID)
	h.issuePair(w, r.Context(), user.ID, user.Username)
}

// handleResend повторно отправляет код подтверждения: новая запись
// замещает старый код и сбрасывает счётчик попыток. Неизвестный или
// уже подтверждённый email — тот же ответ без отправки письма
// (не раскрываем наличие аккаунта).
func (h *handler) handleResend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email is required")
		return
	}
	noop := func() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending_verification"})
	}

	user, err := h.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			h.logger.Error("resend: lookup user", "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "resend failed")
			return
		}
		noop()
		return
	}
	if user.EmailVerified {
		noop()
		return
	}

	// Сначала письмо, потом запись в стор: сбой SMTP не оставляет
	// пользователя без валидного кода — прежний код продолжает работать
	// (замещение происходило до отправки — любой сбой почты сжигал код).
	code := generateVerificationCode()
	if err := h.cfg.Mail.SendCode(r.Context(), user.Email, code, h.cfg.EmailTTL.String()); err != nil {
		h.logger.Error("send verification code", "user_id", user.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to send verification code")
		return
	}
	now := time.Now()
	if err := h.store.SaveEmailVerification(r.Context(), authstore.EmailVerification{
		CodeHash:  hashToken(code),
		UserID:    user.ID,
		ExpiresAt: now.Add(h.cfg.EmailTTL),
		CreatedAt: now,
	}); err != nil {
		h.logger.Error("save email verification", "user_id", user.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "resend failed")
		return
	}

	h.logger.Info("verification code resent", "user_id", user.ID)
	noop()
}

// handleMe отдаёт данные аккаунта владельца access-токена.
func (h *handler) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromBearer(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":     user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"verified":    user.EmailVerified,
		"connect_key": user.ConnectKey,
	})
}

// handleRegenerateConnectKey заменяет connect_key владельца access-токена.
// Подключения, держащие старый ключ, продолжают работать до разрыва —
// ключ проверяется только при подключении.
func (h *handler) handleRegenerateConnectKey(w http.ResponseWriter, r *http.Request) {
	user, ok := h.userFromBearer(w, r)
	if !ok {
		return
	}
	key, err := h.assignConnectKey(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("regenerate connect key", "user_id", user.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to regenerate connect key")
		return
	}
	h.logger.Info("connect key regenerated", "user_id", user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"connect_key": key})
}

// userFromBearer достаёт пользователя из заголовка Authorization:
// Bearer <access-jwt>. При проблемах сам пишет ответ и возвращает false.
func (h *handler) userFromBearer(w http.ResponseWriter, r *http.Request) (authstore.User, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Authorization: Bearer <access_token> is required")
		return authstore.User{}, false
	}
	tok, err := h.tokens.ParseAccessToken([]byte(token))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return authstore.User{}, false
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return authstore.User{}, false
	}
	user, err := h.store.GetUserByID(r.Context(), sub)
	if err != nil {
		if !errors.Is(err, authstore.ErrUserNotFound) {
			// Токен валиден, но стор лежит — это не «невалидный токен».
			h.logger.Error("bearer: lookup user", "user_id", sub, "err", err)
			writeError(w, http.StatusInternalServerError, "server_error", "request failed")
			return authstore.User{}, false
		}
		// Токен валиден, а пользователя нет (например, удалён).
		h.logger.Warn("bearer user not found", "user_id", sub)
		writeError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return authstore.User{}, false
	}
	return user, true
}

// assignConnectKey генерирует ключ и назначает его пользователю;
// при коллизии с чужим ключом генерирует заново.
func (h *handler) assignConnectKey(ctx context.Context, userID string) (string, error) {
	for attempt := 0; attempt < connectKeyAttempts; attempt++ {
		key, err := authstore.GenerateConnectKey()
		if err != nil {
			return "", err
		}
		err = h.store.SetConnectKey(ctx, userID, key)
		if errors.Is(err, authstore.ErrConnectKeyExists) {
			continue
		}
		if err != nil {
			return "", err
		}
		return key, nil
	}
	return "", errors.New("connect key space exhausted")
}

// generateVerificationCode возвращает случайный код из цифр
// (crypto/rand, равномерно: 0…10^len-1).
func generateVerificationCode() string {
	max := 1
	for i := 0; i < VerificationCodeLen; i++ {
		max *= 10
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	n := binary.BigEndian.Uint64(b[:]) % uint64(max)
	return fmt.Sprintf("%0*d", VerificationCodeLen, n)
}

// hashToken — sha256-хеш токена (кода подтверждения, refresh-токена)
// для ключа хранилища.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// handleRevoke отзывает refresh-токен; идемпотентен.
func (h *handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	if err := h.store.RevokeRefresh(r.Context(), hashToken(req.RefreshToken)); err != nil {
		h.logger.Error("revoke refresh token", "err", err)
		writeError(w, http.StatusInternalServerError, "server_error", "revoke failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleJWKS отдаёт публичный набор ключей. Ключи меняются только при
// рестарте, поэтому набор кешируется на минуту.
func (h *handler) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(h.tokens.JWKS()); err != nil {
		h.logger.Error("write jwks", "err", err)
	}
}

func (h *handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		h.logger.Error("write healthz", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Заголовки уже записаны — ничего умнее логировать некуда.
		_ = err
	}
}

func writeError(w http.ResponseWriter, code int, errCode, description string) {
	writeJSON(w, code, errorResponse{Error: errCode, ErrorDescription: description})
}

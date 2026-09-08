package authhttp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// VerificationCodeLen — длина кода подтверждения email (цифры).
const VerificationCodeLen = 6

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

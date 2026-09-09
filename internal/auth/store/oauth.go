package authstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Ошибки OAuth-части хранилища. Сравниваются через errors.Is.
var (
	ErrOAuthClientNotFound = errors.New("authstore: oauth client not found")
	ErrOAuthCodeNotFound   = errors.New("authstore: oauth code not found")
)

// OAuthClient — зарегистрированный OAuth-клиент (MCP-хост). Все клиенты
// публичические (token_endpoint_auth_method=none, секретов нет):
// аутентификация запроса /token — только client_id + PKCE.
type OAuthClient struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	CreatedAt    time.Time
}

// OAuthCode — одноразовый код авторизации. CodeHash — sha256 от исходного
// кода: сам код хранению не подлежит (как у refresh-токенов). Проверка
// PKCE при обмене кода идёт по CodeChallenge/CodeChallengeMethod из
// /authorize; RedirectURI и ClientID сверяются с параметрами обмена.
type OAuthCode struct {
	CodeHash            string
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	CreatedAt           time.Time
}

// OAuthClientLen — длина client_id: 26 символов из 31-буквенного
// алфавита — ~129 бит энтропии (client_id не секрет, но коллизии
// недопустимы: таблица ключуется им).
const OAuthClientLen = 26

// GenerateOAuthClientID возвращает случайный идентификатор OAuth-клиента
// (алфавит и rejection sampling — как у GenerateConnectKey).
func GenerateOAuthClientID() (string, error) {
	out := make([]byte, 0, OAuthClientLen)
	var buf [32]byte
	for len(out) < OAuthClientLen {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", fmt.Errorf("authstore: generate oauth client id: %w", err)
		}
		for _, b := range buf {
			// 248 = 31*8: байты меньше 248 отображаются в алфавит
			// из 31 символа без остаточного перекоса.
			if b >= 248 {
				continue
			}
			out = append(out, connectKeyAlphabet[b%31])
			if len(out) == OAuthClientLen {
				break
			}
		}
	}
	return string(out), nil
}

// GenerateOAuthCode генерирует одноразовый код авторизации: наружу
// отдаётся raw (base64url), в хранилище кладётся sha256-хеш (hex).
func GenerateOAuthCode() (raw, codeHash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("authstore: generate oauth code: %w", err)
	}
	raw = hex.EncodeToString(b[:])
	return raw, hashHex(raw), nil
}

// hashHex — sha256-хеш в hex (хелпер общий с httpapi, но живёт здесь,
// чтобы GenerateOAuthCode закрывал и генерацию, и хеширование).
func hashHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// OAuthStore — работа с OAuth-клиентами (dynamic registration,
// RFC 7591) и одноразовыми кодами авторизации (RFC 6749 + PKCE).
type OAuthStore interface {
	// SaveOAuthClient сохраняет клиента (client_id генерирует
	// вызывающая сторона через GenerateOAuthClientID; коллизии
	// практически невозможны, повторная вставка того же id — ошибка).
	SaveOAuthClient(ctx context.Context, client OAuthClient) error
	// GetOAuthClient ищет клиента по client_id; если нет —
	// ErrOAuthClientNotFound.
	GetOAuthClient(ctx context.Context, clientID string) (OAuthClient, error)
	// SaveOAuthCode сохраняет код авторизации.
	SaveOAuthCode(ctx context.Context, code OAuthCode) error
	// ConsumeOAuthCode атомарно потребляет код (одноразовость:
	// конкурентный обмен одного кода побеждает ровно один вызов)
	// и возвращает его запись. Отсутствующий, истёкший или уже
	// использованный код — ErrOAuthCodeNotFound (проверка истечения —
	// на стороне стора).
	ConsumeOAuthCode(ctx context.Context, codeHash string) (OAuthCode, error)
}

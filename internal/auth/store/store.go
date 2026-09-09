// Пакет authstore — обобщённый интерфейс хранилища auth-сервиса:
// пользователи, refresh-токены, коды подтверждения email и OAuth-сущности
// (клиенты dynamic registration и одноразовые коды авторизации).
// Реализации: internal/auth/store/memory (тесты и разработка) и
// internal/auth/store/postgres (продакшн). Хранилище общее для auth
// и akira-server: сервер ищет пользователя по connect_key при
// подключении клиента.
package authstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// Ошибки хранилища. Сравниваются через errors.Is.
var (
	ErrUserNotFound          = errors.New("authstore: user not found")
	ErrUserExists            = errors.New("authstore: user already exists")
	ErrEmailExists           = errors.New("authstore: email already exists")
	ErrConnectKeyExists      = errors.New("authstore: connect key already exists")
	ErrRefreshNotFound       = errors.New("authstore: refresh token not found")
	ErrVerificationNotFound  = errors.New("authstore: verification code not found")
	ErrVerificationWrongCode = errors.New("authstore: wrong verification code")
)

// MaxVerificationAttempts — предел неверных вводов кода подтверждения
// (защита от перебора: 6 цифр, 5 попыток). После исчерпания нужен resend.
const MaxVerificationAttempts = 5

// ConnectKeyLen — длина connect_key: 10 символов из 31-буквенного
// алфавита — это ~50 бит энтропии; онлайн-перебор по сети невозможен
// за лимитами частоты обратного прокси (см. CLAUDE.md).
const ConnectKeyLen = 10

// connectKeyAlphabet — символы без визуально похожих пар (0/O, 1/l/I
// и т.п.). Длина алфавита (31) используется в GenerateConnectKey:
// граница отбрасывания байтов там — 248 = 31*8.
const connectKeyAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// GenerateConnectKey возвращает случайный connect_key. Распределение
// символов равномерное: байты, дающие перекос по модулю (≥ 248),
// отбрасываются (rejection sampling).
func GenerateConnectKey() (string, error) {
	out := make([]byte, 0, ConnectKeyLen)
	var buf [32]byte
	for len(out) < ConnectKeyLen {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", fmt.Errorf("authstore: generate connect key: %w", err)
		}
		for _, b := range buf {
			// 248 = 31*8: байты меньше 248 отображаются в алфавит
			// из 31 символа без остаточного перекоса.
			if b >= 248 {
				continue
			}
			out = append(out, connectKeyAlphabet[b%31])
			if len(out) == ConnectKeyLen {
				break
			}
		}
	}
	return string(out), nil
}

// User — учётная запись. PasswordHash — bcrypt-хеш; plaintext-пароль
// хранилище не видит никогда. ConnectKey пуст, пока email не подтверждён;
// после верификации — случайный ключ (GenerateConnectKey), по которому
// akira-client подключается от имени пользователя.
type User struct {
	ID            string
	Username      string
	Email         string
	PasswordHash  []byte
	ConnectKey    string
	EmailVerified bool
}

// RefreshToken — запись об opaque refresh-токене. TokenHash — sha256
// от исходного токена: сам токен хранению не подлежит.
type RefreshToken struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// EmailVerification — запись о коде подтверждения email. CodeHash —
// sha256 от кода из письма; код одноразовый (потребление = использование).
// Attempts — число уже засчитанных неверных вводов. Активный код один
// на пользователя; два разных пользователя могут случайно получить
// одинаковый код — это не конфликт (записи независимы).
type EmailVerification struct {
	CodeHash  string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	Attempts  int
}

// UserStore — работа с пользователями.
type UserStore interface {
	// CreateUser создаёт пользователя (email ещё не подтверждён);
	// при занятом имени — ErrUserExists, при занятом email — ErrEmailExists.
	CreateUser(ctx context.Context, username, email string, passwordHash []byte) (User, error)
	// CreateUserWithCode атомарно создаёт пользователя и его первый код
	// подтверждения email: частичный результат (пользователь без кода)
	// невозможен. Ошибки конфликтов — как у CreateUser. Кодом затем
	// завершают верификацию через CompleteEmailVerification.
	CreateUserWithCode(ctx context.Context, username, email string, passwordHash []byte, codeHash string, codeExpiresAt time.Time) (User, error)
	// GetUserByUsername ищет пользователя по имени; если нет — ErrUserNotFound.
	GetUserByUsername(ctx context.Context, username string) (User, error)
	// GetUserByEmail ищет пользователя по адресу email; если нет —
	// ErrUserNotFound. Нужен форме верификации: код вводится вместе с email.
	GetUserByEmail(ctx context.Context, email string) (User, error)
	// GetUserByID ищет пользователя по user_id; если нет — ErrUserNotFound.
	// Нужен эндпоинту /me: access-токен несёт в sub именно user_id.
	GetUserByID(ctx context.Context, userID string) (User, error)
	// GetUserByConnectKey ищет подтверждённого пользователя по ключу
	// подключения; если нет — ErrUserNotFound. Используется akira-server.
	GetUserByConnectKey(ctx context.Context, connectKey string) (User, error)
	// VerifyEmail помечает email пользователя подтверждённым.
	VerifyEmail(ctx context.Context, userID string) error
	// SetConnectKey назначает пользователю ключ подключения (перегенерация);
	// занятый ключ — ErrConnectKeyExists.
	SetConnectKey(ctx context.Context, userID, connectKey string) error
}

// RefreshStore — работа с refresh-токенами.
type RefreshStore interface {
	// SaveRefresh сохраняет запись о токене.
	SaveRefresh(ctx context.Context, tok RefreshToken) error
	// RotateRefresh атомарно потребляет старый refresh-токен и сохраняет
	// новый (ротация): запись по oldTokenHash удаляется, newTok
	// вставляется с user_id из старой записи. Отсутствующий, истёкший
	// или уже использованный токен — ErrRefreshNotFound (проверка
	// истечения — на стороне стора); новый токен при этом не сохраняется.
	// Возвращает потреблённую запись. Побеждает ровно один конкурентный
	// вызов с одним и тем же старым токеном.
	RotateRefresh(ctx context.Context, oldTokenHash string, newTok RefreshToken) (RefreshToken, error)
	// RevokeRefresh удаляет запись; идемпотентна (отсутствие записи — не ошибка).
	RevokeRefresh(ctx context.Context, tokenHash string) error
}

// EmailVerificationStore — работа с кодами подтверждения email.
type EmailVerificationStore interface {
	// SaveEmailVerification сохраняет запись о коде (новая запись
	// замещает предыдущую и сбрасывает счётчик попыток — активный код
	// один на пользователя). Проверка истечения — на стороне стора,
	// при CompleteEmailVerification.
	SaveEmailVerification(ctx context.Context, tok EmailVerification) error
	// CompleteEmailVerification атомарно сверяет и потребляет код,
	// помечает email подтверждённым и назначает connect_key. Не совпал —
	// попытка засчитывается, ErrVerificationWrongCode. Записи нет, код
	// истёк или попытки исчерпаны — ErrVerificationNotFound. Занятый
	// connect_key — ErrConnectKeyExists, причём код не потребляется:
	// вызов можно повторить с другим ключом.
	CompleteEmailVerification(ctx context.Context, userID, codeHash, connectKey string) error
}

// Store — полное хранилище auth-сервиса: одна реализация закрывает
// все четыре интерфейса.
type Store interface {
	UserStore
	RefreshStore
	EmailVerificationStore
	OAuthStore
}

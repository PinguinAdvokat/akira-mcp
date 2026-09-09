// Пакет akiramcp — MCP-интерфейс akira: выставляет машины пользователя
// (акти-клиенты, подключённые к пулу) как ресурсы и инструменты MCP,
// чтобы LLM мог управлять ими — читать файлы, писать файлы и исполнять
// команды.
//
// Авторизация: MCP-клиент предъявляет access-токен auth-сервиса
// (RS256 JWT) в заголовке Authorization: Bearer. Токен проверяется
// автономно по JWKS auth-сервиса — как внешний потребитель: подпись,
// iss, сроки, claim typ="access". user_id из claim sub задаёт владельца:
// все операции ограничены подключениями с префиксом {user_id}:,
// поэтому один пользователь не видит и не трогает машины другого.
//
// Файлы пакета: auth.go — проверка токенов; tools.go — инструменты
// exec и write_file; resources.go — ресурсы akira://machines и
// akira://file/{client_id}/{+path}; server.go — сборка HTTP-хендлера.
package akiramcp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ErrNoAuthorization — в запросе нет заголовка Authorization: Bearer.
var ErrNoAuthorization = errors.New("akiramcp: missing bearer token")

// ErrNotAccessToken — токен не является access-токеном (claim typ).
var ErrNotAccessToken = errors.New("akiramcp: token is not an access token")

// TokenValidator проверяет access-токены auth-сервиса по его JWKS.
// Набор ключей не загружается при создании: кэш тянет его при первом
// токене. Ключи auth-сервиса живут только в памяти его процесса
// (рестарт меняет kid), поэтому при неизвестном kid набор рефечится
// с ограничением частоты — не чаще раза в refreshInterval.
type TokenValidator struct {
	jwksURL string
	issuer  string

	cache *jwk.Cache

	refreshMu   sync.Mutex
	lastRefresh time.Time
}

// refreshInterval — минимальная пауза между принудительными рефечами
// JWKS при неизвестном kid: защита от DoS auth-сервиса лавиной
// токенов с посторонними kid (каждый такой запускал бы рефеч).
const refreshInterval = 30 * time.Second

// NewTokenValidator создаёт валидатор. jwksURL — адрес JWKS auth-сервиса
// (например http://127.0.0.1:6000/jwks.json), issuer — ожидаемое
// значение claim iss (AUTH_ISSUER auth-сервиса, по умолчанию "akira").
// Недоступный auth при старте не фатален: первая загрузка набора
// случится при проверке первого токена.
func NewTokenValidator(ctx context.Context, jwksURL, issuer string) (*TokenValidator, error) {
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, err
	}
	if err := cache.Register(ctx, jwksURL); err != nil {
		return nil, err
	}
	return &TokenValidator{
		jwksURL: jwksURL,
		issuer:  issuer,
		cache:   cache,
	}, nil
}

// Validate проверяет Bearer-токен из запроса и возвращает user_id
// (claim sub). Токен проверяется тем же путём, что и внешний
// потребитель: подпись по JWKS (kid обязателен), iss, exp/iat
// и typ="access".
func (v *TokenValidator) Validate(ctx context.Context, r *http.Request) (string, error) {
	raw := bearerToken(r)
	if raw == "" {
		return "", ErrNoAuthorization
	}

	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(v.keySet(ctx), jws.WithRequireKid(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
	)
	if err != nil {
		// Неизвестный kid (после рестарта auth-сервиса старый JWKS
		// неактуален): рефечим набор и проверяем ещё раз. Идентифицируем
		// по тексту — jwx не экспонирует типизированную ошибку для
		// «kid нет в наборе».
		if strings.Contains(err.Error(), `in key set`) {
			tok, err = jwt.Parse([]byte(raw),
				jwt.WithKeySet(v.refreshKeySet(ctx), jws.WithRequireKid(true)),
				jwt.WithValidate(true),
				jwt.WithIssuer(v.issuer),
			)
		}
		if err != nil {
			return "", err
		}
	}
	sub, _ := tok.Subject()
	if sub == "" {
		return "", errors.New("akiramcp: token has empty sub")
	}
	var typ string
	if err := tok.Get("typ", &typ); err != nil || typ != "access" {
		return "", ErrNotAccessToken
	}
	return sub, nil
}

// keySet возвращает CachedSet над зарегистрированным JWKS: ключи
// достаются по kid из кэша (кэш подтянет набор, если он ещё не готов).
func (v *TokenValidator) keySet(ctx context.Context) jwk.Set {
	set, err := v.cache.CachedSet(v.jwksURL)
	if err != nil {
		// URL зарегистрирован в NewTokenValidator — ошибка возможна
		// только при отмене ctx; возвращаем пустой набор, jwt.Parse
		// ответит ошибкой верификации.
		return jwk.NewSet()
	}
	return set
}

// refreshKeySet рефечит JWKS (не чаще раза в refreshInterval — защиту
// от закладки подложных «неизвестных kid») и возвращает свежий
// CachedSet.
func (v *TokenValidator) refreshKeySet(ctx context.Context) jwk.Set {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	if time.Since(v.lastRefresh) < refreshInterval {
		return v.keySet(ctx)
	}
	v.lastRefresh = time.Now()
	_, _ = v.cache.Refresh(ctx, v.jwksURL)
	return v.keySet(ctx)
}

// bearerToken достаёт токен из заголовка Authorization
// (схема Bearer, регистронезависимая).
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}

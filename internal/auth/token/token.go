// Пакет authtoken — выдача и подпись токенов auth-сервиса.
//
// Access-токен — JWT (RS256, RSA-2048) с claims iss, sub, jti, iat,
// exp и typ="access". Публичный ключ публикуется через JWKS:
// сервисы-потребители проверяют подпись access-токена автономно,
// не обращаясь к auth-сервису.
//
// Refresh-токен — opaque: 32 случайных байта base64url, на сервере
// хранится только sha256-хеш (см. authstore). JWT для refresh ничего
// не даёт: потребители его не проверяют, а серверное состояние даёт
// мгновенный отзыв и одноразовую ротацию.
//
// Ключи живут только в памяти процесса: kid генерируется заново при
// каждом запуске, поэтому после рестарта все ранее выданные токены
// невалидны. Потребители JWKS должны рефетчить набор при неизвестном
// kid (jws.WithRequireKid + jwt.WithVerifyAuto в будущих интеграциях
// дают это автоматически). Ротация ключей — вне скоупа.
package authtoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// newID возвращает случайный hex-идентификатор (kid / jti).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	return hex.EncodeToString(b[:])
}

// Manager выпускает токены и публикует JWKS для их проверки.
type Manager struct {
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration

	privJWK jwk.Key
	jwks    []byte // иммутабелен после создания: MarshalJSON один раз
}

// NewManager генерирует RSA-2048 пару и kid. Ключи не сохраняются —
// см. док-комментарий пакета.
func NewManager(issuer string, accessTTL, refreshTTL time.Duration) (*Manager, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := newID()

	privJWK, err := jwk.Import(priv)
	if err != nil {
		return nil, err
	}
	if err := privJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	// kid из jwk.Key автоматически попадает в protected header подписи.

	pubJWK, err := jwk.Import(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	// alg обязателен: jwt.WithKeySet не берёт ключи без указанного алгоритма.
	_ = pubJWK.Set(jwk.KeyIDKey, kid)
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.RS256().String())
	_ = pubJWK.Set(jwk.KeyUsageKey, "sig")

	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		return nil, err
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}

	return &Manager{
		issuer:     issuer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		privJWK:    privJWK,
		jwks:       jwks,
	}, nil
}

// NewAccessToken подписывает access-JWT для пользователя userID.
func (m *Manager) NewAccessToken(userID string) (string, error) {
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(m.issuer).
		Subject(userID).
		JwtID(newID()).
		IssuedAt(now).
		Expiration(now.Add(m.accessTTL)).
		Claim("typ", "access").
		Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), m.privJWK))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// NewRefreshToken генерирует opaque refresh-токен: наружу отдаётся
// raw (base64url), в хранилище кладётся tokenHash (sha256, hex).
// Срок жизни записи — RefreshTTL().
func (m *Manager) NewRefreshToken() (raw, tokenHash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

// RefreshTTL — срок жизни refresh-токена (для ExpiresAt записи в хранилище).
func (m *Manager) RefreshTTL() time.Duration {
	return m.refreshTTL
}

// AccessTTL — срок жизни access-токена (для expires_in в ответе).
func (m *Manager) AccessTTL() time.Duration {
	return m.accessTTL
}

// JWKS возвращает JSON публичного набора ключей
// ({"keys":[{kty,e,n,kid,alg,use}]}), приватных полей нет.
func (m *Manager) JWKS() []byte {
	return m.jwks
}

// ParseAccessToken проверяет access-токен по собственному JWKS:
// подпись (kid обязателен), iss и сроки. Служит для тестов и
// интеграций внутри процесса.
func (m *Manager) ParseAccessToken(data []byte) (jwt.Token, error) {
	return jwt.Parse(data,
		jwt.WithKeySet(m.keySet(), jws.WithRequireKid(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(m.issuer),
	)
}

// keySet разбирает собственный JWKS обратно в jwk.Set — так проверка
// идёт тем же путём, что и у внешних потребителей.
func (m *Manager) keySet() jwk.Set {
	set, err := jwk.Parse(m.jwks)
	if err != nil {
		panic(err) // JWKS построен нами самими и обязан парситься
	}
	return set
}

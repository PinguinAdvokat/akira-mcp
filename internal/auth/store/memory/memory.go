// Пакет authstorememory — in-memory реализация authstore.Store
// без сохранения на диск: всё пропадает при рестарте процесса.
// Реализация для разработки и тестов; продакшн-цель — Postgres.
//
// Файлы пакета симметричны postgres-стору: memory.go — хранилище
// и конструктор; users.go — пользователи; refresh.go — refresh-токены;
// verification.go — коды подтверждения email.
package authstorememory

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// newID возвращает случайный hex-идентификатор пользователя
// (по образцу connection.NewID).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	return hex.EncodeToString(b[:])
}

// Store — in-memory хранилище. Потокобезопасно: хендлеры HTTP
// обращаются к нему конкурентно, а одноразовость токенов и кодов
// (RotateRefresh, CompleteEmailVerification) обязана быть атомарной.
type Store struct {
	mu      sync.Mutex
	users   map[string]authstore.User              // username → User
	byID    map[string]string                      // user ID → username
	byEmail map[string]string                      // email → username
	byKey   map[string]string                      // connect_key → user ID
	refr    map[string]authstore.RefreshToken      // tokenHash → RefreshToken
	verifs  map[string]authstore.EmailVerification // userID → активный код
}

// New создаёт пустое хранилище.
func New() *Store {
	return &Store{
		users:   make(map[string]authstore.User),
		byID:    make(map[string]string),
		byEmail: make(map[string]string),
		byKey:   make(map[string]string),
		refr:    make(map[string]authstore.RefreshToken),
		verifs:  make(map[string]authstore.EmailVerification),
	}
}

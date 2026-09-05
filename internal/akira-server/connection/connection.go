package connection

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	// ErrAlreadyRegistered — клиент с таким client_id уже подключен.
	ErrAlreadyRegistered = errors.New("connectionpool: client already registered")
	// ErrConnectionNotFound — активного подключения с таким client_id нет.
	ErrConnectionNotFound = errors.New("connectionpool: connection not found")
	// ErrConnectionClosed — подключение закрыто.
	ErrConnectionClosed = errors.New("connectionpool: connection closed")
)

// newID возвращает случайный hex-идентификатор (session_id / task id).
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	return hex.EncodeToString(b[:])
}

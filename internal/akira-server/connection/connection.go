package connection

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	// ErrAlreadyRegistered — подключение с таким connection_id уже активно.
	ErrAlreadyRegistered = errors.New("connectionpool: client already registered")
	// ErrConnectionNotFound — активного подключения с таким connection_id нет.
	ErrConnectionNotFound = errors.New("connectionpool: connection not found")
	// ErrConnectionClosed — подключение закрыто.
	ErrConnectionClosed = errors.New("connectionpool: connection closed")
	// ErrTaskAlreadyPending — задача с таким task_id уже ожидает результат.
	ErrTaskAlreadyPending = errors.New("connectionpool: task id is already pending")
	// ErrNotTaskOwner — результат прислало не то подключение, которому
	// отправлена задача.
	ErrNotTaskOwner = errors.New("connectionpool: result submitted by a non-owner client")
	// ErrTooManyConnections — пользователь превысил лимит одновременных
	// подключений (MAX_CONNECTIONS).
	ErrTooManyConnections = errors.New("connectionpool: too many connections for user")
)

// newID возвращает случайный hex-идентификатор (session_id / task id).
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не должен падать
	}
	return hex.EncodeToString(b[:])
}

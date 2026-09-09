package connectionpool

import (
	"sort"
	"strings"
	"sync"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection"
	"github.com/PinguinAdvokat/akira-mcp/internal/akira-server/connection/client"
)

// ClientInfo — паспорт активного подключения: идентификаторы
// плюс hostname и platform из RegisterRequest (клиент сообщает их
// при регистрации). ConnectionID имеет формат {user_id}:{client_id};
// поле ClientID — часть после двоеточия.
type ClientInfo struct {
	ConnectionID string
	ClientID     string
	Hostname     string
	Platform     string
}

// ConnectionPool хранит активные подключения по connection_id
// ({user_id}:{client_id}) и реестр задач, ожидающих результат, по task_id.
// Через SendTask любые объекты сервера могут отправлять задачи на
// исполнение клиенту; результаты приходят через SubmitResult
// и маршрутизируются по task_id. Ожидание результата не переживает
// разрыв соединения: при потере подключения все задачи клиента
// завершаются ошибкой ErrConnectionClosed — и отправленные, и не
// успевшие уйти.
//
// Файлы пакета: pool.go — реестр подключений; pending.go — корреляция
// задач и результатов (SendTask / HandleResult и сбои ожидания).
type ConnectionPool struct {
	mu             sync.RWMutex
	conns          map[string]*client.ClientConnection
	infos          map[string]ClientInfo
	pending        map[string]*pendingEntry
	maxConnections int // лимит одновременных подключений на пользователя; 0 = без лимита
}

// New создаёт пул. maxConnections — лимит одновременных подключений
// на одного пользователя (MAX_CONNECTIONS); 0 — без лимита.
func New(maxConnections int) *ConnectionPool {
	return &ConnectionPool{
		conns:          make(map[string]*client.ClientConnection),
		infos:          make(map[string]ClientInfo),
		pending:        make(map[string]*pendingEntry),
		maxConnections: maxConnections,
	}
}

// Register добавляет новое подключение в пул под connection_id
// ({user_id}:{client_id}) и запоминает его метаданные info.
// Возвращает ErrAlreadyRegistered, если подключение с таким
// connection_id уже активно, и ErrTooManyConnections, если пользователь
// превысил лимит одновременных подключений.
func (p *ConnectionPool) Register(connectionID, userID string, info ClientInfo) (*client.ClientConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.conns[connectionID]; ok {
		return nil, connection.ErrAlreadyRegistered
	}
	if p.maxConnections > 0 && p.countByUser(userID) >= p.maxConnections {
		return nil, connection.ErrTooManyConnections
	}
	c := client.New(connectionID)
	p.conns[connectionID] = c
	info.ConnectionID = connectionID
	info.ClientID = strings.TrimPrefix(connectionID, userID+":")
	p.infos[connectionID] = info
	return c, nil
}

// countByUser считает активные подключения пользователя по префиксу
// {user_id}: — user_id фиксированной длины (hex), неоднозначности
// разделителя нет. Вызывать под p.mu.
func (p *ConnectionPool) countByUser(userID string) int {
	prefix := userID + ":"
	n := 0
	for id := range p.conns {
		if strings.HasPrefix(id, prefix) {
			n++
		}
	}
	return n
}

// Unregister убирает подключение из пула и завершает ошибкой
// ErrConnectionClosed ожидание всех задач подключения — результата
// по ним можно не ждать, даже если клиент переподключится:
// переподключение не пересылает уже отправленные задачи заново.
// Если в пуле уже другое, более новое подключение (гонка
// переподключения) — только завершает задачи, сообщения о которых
// не ушли из очереди старого подключения: клиент на связи, и
// отправленные ему задачи могут ещё доставить результат.
func (p *ConnectionPool) Unregister(conn *client.ClientConnection) {
	p.mu.Lock()
	cur, ok := p.conns[conn.ClientID]
	if !ok || cur != conn {
		p.mu.Unlock()
		if ok {
			p.failUnsent(conn.Close())
		}
		return
	}
	delete(p.conns, conn.ClientID)
	delete(p.infos, conn.ClientID)
	p.mu.Unlock()
	conn.Close()
	p.failPendingClient(conn.ClientID)
}

// Disconnect разрывает текущее подключение: атомарно убирает
// его из пула (за одну блокировку — между чтением и удалением подключение
// не успеет смениться на новое при переподключении), завершает поток
// Connect и возвращает true. Возвращает false, если подключение не активно.
// Все задачи подключения (и отправленные, и не ушедшие) завершаются
// ошибкой ErrConnectionClosed.
func (p *ConnectionPool) Disconnect(connectionID string) bool {
	p.mu.Lock()
	c, ok := p.conns[connectionID]
	if ok {
		delete(p.conns, connectionID)
		delete(p.infos, connectionID)
	}
	p.mu.Unlock()
	if !ok {
		return false
	}
	c.Close()
	p.failPendingClient(connectionID)
	return true
}

// ClientIDs возвращает отсортированный список connection_id активных
// подключений ({user_id}:{client_id}).
func (p *ConnectionPool) ClientIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.conns))
	for id := range p.conns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Has сообщает, активно ли подключение с данным connection_id.
func (p *ConnectionPool) Has(connectionID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.conns[connectionID]
	return ok
}

// ClientsByUser возвращает метаданные активных подключений пользователя
// (фильтр по префиксу {user_id}:). Список отсортирован по connection_id —
// вывод стабилен между вызовами.
func (p *ConnectionPool) ClientsByUser(userID string) []ClientInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	prefix := userID + ":"
	infos := make([]ClientInfo, 0, len(p.infos))
	for id, info := range p.infos {
		if strings.HasPrefix(id, prefix) {
			infos = append(infos, info)
		}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ConnectionID < infos[j].ConnectionID })
	return infos
}

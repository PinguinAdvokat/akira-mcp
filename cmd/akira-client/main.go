package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net"

	"github.com/PinguinAdvokat/akira-mcp/internal/akira-client/connection"
)

var (
	// serverAddr — адрес akira-server, задаётся флагом -server.
	serverAddr = flag.String("server", "localhost:5000", "akira-server address (host:port)")
	// clientID — уникальный идентификатор клиента, задаётся флагом -client-id.
	clientID = flag.String("client-id", "", "unique client id (required)")
	// connectKey — короткий ключ пользователя из auth-сервиса.
	connectKey = flag.String("connect-key", "", "user connect key from the auth service (required)")
	// retryDelay — пауза между попытками переподключения.
	retryDelay = flag.Duration("retry-delay", 0, "pause between reconnect attempts (0 = 3s)")
	// useTLS — включить TLS-шифрование соединения (терминируется прокси).
	useTLS = flag.Bool("tls", false, "connect over TLS")
	// tlsInsecure — пропустить проверку сертификата сервера (dev-режим,
	// самоподписанный сертификат).
	tlsInsecure = flag.Bool("tls-insecure", false, "skip server certificate verification (self-signed certs)")
	// tlsServerName — имя для проверки сертификата, если адрес — IP
	// (сертификат обычно выписан на домен).
	tlsServerName = flag.String("tls-server-name", "", "server name for certificate verification (override SNI)")
)

func main() {
	flag.Parse()
	if *clientID == "" {
		log.Fatal("the -client-id flag is required")
	}
	if *connectKey == "" {
		log.Fatal("the -connect-key flag is required")
	}

	// TLS-конфигурация: по умолчанию проверка через системные CA;
	// -tls-insecure отключает проверку (самоподписанный сертификат
	// без CA-файла), -tls-server-name подменяет имя для проверки.
	var tlsConf *tls.Config
	if *useTLS {
		if !*tlsInsecure && *tlsServerName == "" && isIPOnly(*serverAddr) {
			log.Fatal("-tls-server-name is required when connecting to a bare IP with certificate verification")
		}
		tlsConf = &tls.Config{
			InsecureSkipVerify: *tlsInsecure, //nolint:gosec // осознанный dev-режим
			ServerName:         *tlsServerName,
		}
	}

	// Логика подключения — в internal/akira-client/connection:
	// client_id не меняется, при разрыве клиент переподключается
	// с тем же id, выполняемые задачи не прерываются. Пользователь
	// определяется сервером по connect_key.
	if err := connection.Run(context.Background(), connection.Config{
		ServerAddr: *serverAddr,
		ClientID:   *clientID,
		ConnectKey: *connectKey,
		RetryDelay: *retryDelay,
		TLS:        tlsConf,
	}); err != nil {
		log.Fatal(err)
	}
}

// isIPOnly сообщает, состоит ли host:port только из IP-адреса
// (без домена): проверка сертификата по IP почти всегда провалится,
// лучше сразу потребовать -tls-server-name.
func isIPOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

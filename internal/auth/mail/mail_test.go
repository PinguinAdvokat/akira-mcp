package authmail

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// discardLogger — логгер, выбрасывающий вывод (ошибки отправки
// логируются, в тестах это шум).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestLogSender: без SMTP код логируется, ошибки нет.
func TestLogSender(t *testing.T) {
	s := &logSender{logger: discardLogger()}
	if err := s.SendCode(context.Background(), "user@example.com", "123456", "15m"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
}

// TestSMTPSenderDeliversCode: полный диалог с заглушкой SMTP-сервера —
// письмо доходит, код и адресат в теле письма.
func TestSMTPSenderDeliversCode(t *testing.T) {
	addr, delivered := stubSMTPServer(t)

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	s := &smtpSender{
		cfg:    Config{Host: host, Port: port, From: "akira@test"},
		logger: discardLogger(),
	}

	if err := s.SendCode(context.Background(), "user@example.com", "123456", "15m"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}

	select {
	case body := <-delivered:
		if !strings.Contains(body, "Your confirmation code: 123456") {
			t.Fatalf("body must contain the code: %q", body)
		}
		if !strings.Contains(body, "To: user@example.com") {
			t.Fatalf("body must address the recipient: %q", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no message delivered")
	}
}

// TestSMTPSenderSilentServerTimesOut: сервер принимает соединение
// и молчит — дедлайн контекста обязан прервать ожидание приветствия,
// а не висеть до SMTP-таймаутов хоста.
func TestSMTPSenderSilentServerTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Принимаем соединения и держим их открытыми, ничего не отвечая.
	go func() {
		var held []net.Conn
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	s := &smtpSender{
		cfg:    Config{Host: host, Port: port, From: "akira@test"},
		logger: discardLogger(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := s.SendCode(ctx, "user@example.com", "123456", "15m"); err == nil {
		t.Fatal("silent server must produce an error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("deadline must abort quickly, took %v", elapsed)
	}
}

// stubSMTPServer поднимает минимальный SMTP-сервер без AUTH и STARTTLS
// на случайном порту и возвращает канал с телами доставленных писем.
func stubSMTPServer(t *testing.T) (addr string, delivered chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	delivered = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		r := bufio.NewReader(conn)
		write := func(s string) {
			if _, err := conn.Write([]byte(s + "\r\n")); err != nil {
				return
			}
		}
		write("220 stub ESMTP")

		var body strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")

			if inData {
				if line == "." {
					write("250 OK")
					inData = false
					select {
					case delivered <- body.String():
					default:
					}
					body.Reset()
				} else {
					body.WriteString(line + "\n")
				}
				continue
			}

			switch {
			case strings.HasPrefix(line, "EHLO"):
				write("250-stub")
				write("250 8BITMIME") // без AUTH и STARTTLS
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				write("250 OK")
			case line == "DATA":
				write("354 go ahead")
				inData = true
			case line == "QUIT":
				write("221 bye")
				return
			default:
				write("250 OK")
			}
		}
	}()
	return ln.Addr().String(), delivered
}

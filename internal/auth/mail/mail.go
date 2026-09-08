// Пакет authmail — отправка писем auth-сервиса. Единственный вид
// письма сейчас — подтверждение email: письмо с коротким кодом,
// который пользователь вводит в форму на фронте. Если SMTP
// не настроен, используется logSender: код пишется в лог
// (режим локальной разработки).
package authmail

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// Sender отправляет письмо с кодом подтверждения email: to — адресат,
// code — код подтверждения, ttl — срок его жизни (для текста письма).
type Sender interface {
	SendCode(ctx context.Context, to, code, ttl string) error
}

// Config — параметры SMTP из переменных окружения.
type Config struct {
	Host string // SMTP_HOST; пустое значение — SMTP выключен (logSender)
	Port int    // SMTP_PORT, по умолчанию 587
	User string // SMTP_USER
	Pass string // SMTP_PASS
	From string // SMTP_FROM, по умолчанию akira@localhost
}

// ConfigFromEnv собирает конфиг SMTP из окружения.
func ConfigFromEnv() Config {
	cfg := Config{
		Host: os.Getenv("SMTP_HOST"),
		User: os.Getenv("SMTP_USER"),
		Pass: os.Getenv("SMTP_PASS"),
		From: os.Getenv("SMTP_FROM"),
		Port: 587,
	}
	if raw := os.Getenv("SMTP_PORT"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil && p > 0 {
			cfg.Port = p
		}
	}
	if cfg.From == "" {
		cfg.From = "akira@localhost"
	}
	return cfg
}

// New выбирает отправитель по конфигу: без SMTP_HOST — logSender.
func New(cfg Config, logger *slog.Logger) Sender {
	if cfg.Host == "" {
		return &logSender{logger: logger}
	}
	return &smtpSender{cfg: cfg, logger: logger}
}

// smtpTimeout — потолок на всё SMTP-общение (диалог + DATA): зависший
// сервер не должен держать HTTP-хендлер бесконечно. Кратчайший дедлайн
// контекста ограничивает его сильнее.
const smtpTimeout = 15 * time.Second

// smtpSender отправляет письма через SMTP (stdlib net/smtp, но с
// собственным диалогом вместо smtp.SendMail: SendMail игнорирует
// контекст и не умеет дедлайны).
type smtpSender struct {
	cfg    Config
	logger *slog.Logger
}

// message собирает текст письма с кодом подтверждения.
func (s *smtpSender) message(to, code, ttl string) string {
	return strings.Join([]string{
		"From: " + s.cfg.From,
		"To: " + to,
		"Subject: Akira: confirmation code",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"Your confirmation code: " + code,
		"",
		"The code is valid for " + ttl + ".",
		"",
		"If you did not register, just ignore this email.",
	}, "\r\n")
}

// SendCode отправляет письмо с кодом подтверждения. Контекст и
// smtpTimeout ограничивают и установление соединения, и каждый шаг
// SMTP-диалога (дедлайн на сокете).
func (s *smtpSender) SendCode(ctx context.Context, to, code, ttl string) error {
	if err := s.send(ctx, to, s.message(to, code, ttl)); err != nil {
		s.logger.Error("send verification code email", "to", to, "err", err)
		return err
	}
	return nil
}

// send ведёт SMTP-диалог: EHLO → STARTTLS (если сервер предлагает) →
// AUTH → MAIL/RCPT/DATA → QUIT.
func (s *smtpSender) send(ctx context.Context, to, msg string) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	// Дедлайн диалога: smtpTimeout, но не позже дедлайна контекста.
	deadline := time.Now().Add(smtpTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("authmail: dial %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("authmail: set deadline: %w", err)
	}

	// Отмена контекста разрывает зависший диалог: SetDeadline сам по
	// себе ctx не видит, поэтому watchdog дёргает дедлайн сокета.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now()) // будит блокированные чтение/запись
		case <-watchDone:
		}
	}()

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("authmail: smtp greeting from %s: %w", addr, err)
	}
	defer c.Close()

	// STARTTLS, если сервер предлагает: код подтверждения не должен
	// идти по открытому каналу.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host}); err != nil {
			return fmt.Errorf("authmail: starttls with %s: %w", addr, err)
		}
	} else if s.cfg.User != "" && !isLocalhost(s.cfg.Host) {
		// Как и net/smtp.PlainAuth, не шлём учётные данные по открытому
		// каналу (исключение — локальный релей для разработки).
		return fmt.Errorf("authmail: %s does not offer STARTTLS; refusing to send credentials in plaintext", addr)
	}

	if s.cfg.User != "" {
		if err := c.Auth(smtp.PlainAuth("", s.cfg.User, s.cfg.Pass, s.cfg.Host)); err != nil {
			return fmt.Errorf("authmail: auth with %s: %w", addr, err)
		}
	}

	if err := c.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("authmail: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("authmail: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("authmail: DATA: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("authmail: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("authmail: submit body: %w", err)
	}
	// Письмо уже принято после закрытия DATA; ошибка QUIT не делает
	// отправку неудавшейся (иначе был бы повтор и дубликат письма).
	_ = c.Quit()
	return nil
}

// isLocalhost — адреса, для которых net/smtp.PlainAuth допускает
// открытый канал (локальная разработка без TLS).
func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// logSender пишет код подтверждения в лог — режим разработки
// без настроенного SMTP.
type logSender struct {
	logger *slog.Logger
}

// SendCode логирует код подтверждения.
func (s *logSender) SendCode(_ context.Context, to, code, ttl string) error {
	s.logger.Info("verification code (SMTP disabled, code logged)",
		"to", to, "code", code, "ttl", ttl)
	return nil
}

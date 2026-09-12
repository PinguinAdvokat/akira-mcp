package akiramcp

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"text/template"
)

// defaultClientReleasesURL — база релизов GitHub по умолчанию,
// откуда скрипт /sh качает бинарник akira-client.
// Переопределяется через Config.ClientReleasesURL (env MCP_CLIENT_RELEASES_URL).
const defaultClientReleasesURL = "https://github.com/PinguinAdvokat/akira-mcp/releases"

// installScript — bash-скрипт установки akira-client (GET /sh).
// Плейсхолдеры: {{.ReleasesURL}}, {{.ServerAddr}}, {{.TLSFlags}} —
// text/template, чтобы '%' и '$' самого скрипта не трогались.
// Скрипт совместим с bash 3.2 (macOS): нет ${var,,} и mapfile,
// регистр приводится через tr, mktemp — с шаблоном X.
const installScript = `#!/usr/bin/env bash
# Установка и запуск akira-client. Сгенерировано akira-server (GET /sh).
# Использование: bash <(curl -sL https://<host>/sh) <connect_key>
set -euo pipefail

key="${1:-}"
if [ -z "$key" ]; then
  read -r -p "Connect key: " key < /dev/tty || true
fi
[ -n "$key" ] || { echo "error: connect key is required" >&2; exit 1; }

# ОС и архитектура → имя ассета релиза.
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux|darwin) ;;
  *) echo "error: unsupported OS: $os" >&2; exit 1 ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
esac

url="{{.ReleasesURL}}/latest/download/akira-client-${os}-${arch}"
bin=/tmp/akira-client
log=/tmp/akira-client.log

# Скачиваем во временный файл, затем атомарный mv: оборванная
# загрузка не оставит битый бинарник на целевом пути. curl -f —
# чтобы 404 от GitHub (нет ассета под эту платформу) не превратился
# в chmod исполняемой HTML-страницы.
tmp="$(mktemp "${bin}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
echo "downloading akira-client (${os}/${arch})..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 -o "$tmp" "$url" || { echo "error: download failed: $url" >&2; exit 1; }
elif command -v wget >/dev/null 2>&1; then
  wget -q --tries=3 -O "$tmp" "$url" || { echo "error: download failed: $url" >&2; exit 1; }
else
  echo "error: curl or wget is required" >&2; exit 1
fi
chmod +x "$tmp"
mv -f "$tmp" "$bin"
trap - EXIT

# Уже запущенный клиент с тем же client_id бесконечно ретраит
# (connection_id занят, AlreadyExists не фатален для клиента) —
# предлагаем остановить старый процесс.
if command -v pgrep >/dev/null 2>&1 && pgrep -x akira-client >/dev/null 2>&1; then
  echo "akira-client is already running."
  answer=n
  read -r -p "Stop it and start a new one? [y/N] " answer < /dev/tty || true
  if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    pkill -x akira-client || true
    sleep 1
  fi
fi

# client_id: пустой ввод → имя хоста.
default_id="$(hostname)"
read -r -p "Client ID [${default_id}]: " client_id < /dev/tty || true
client_id="${client_id:-$default_id}"

echo "starting akira-client (client_id=${client_id})..."
nohup "$bin" -server "{{.ServerAddr}}" {{.TLSFlags}} \
  -client-id "$client_id" -connect-key "$key" >>"$log" 2>&1 &
pid=$!
echo "$pid" > /tmp/akira-client.pid
echo "started (pid ${pid}); logs: tail -f ${log}"
`

// installScriptTmpl — шаблон установочного скрипта; парсится один
// раз при первом использовании, синтаксическая ошибка — паника
// старта, а не 500 в рантайме.
var installScriptTmpl = template.Must(template.New("install").Parse(installScript))

// installParams — значения, зашиваемые в installScript при старте.
type installParams struct {
	ReleasesURL string
	ServerAddr  string
	TLSFlags    string
}

// renderInstallScript собирает установочный скрипт один раз при
// старте сервера.
func renderInstallScript(p installParams) (string, error) {
	var buf bytes.Buffer
	if err := installScriptTmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("execute install script template: %w", err)
	}
	return buf.String(), nil
}

// clientConnectParams выводит из PublicURL адрес akira-server
// (-server) и TLS-флаги для akira-client. Предполагается развертывание
// за единственным nginx (compose): gRPC (/akira.connection.v1.../)
// и MCP слушают один и тот же публичный порт, поэтому порт берём
// из PublicURL, дефолт — по scheme (https→443, http→80). Для https
// по bare IP сертификат проверить нечем — включаем -tls-insecure
// (dev-сценарий с самоподписанным сертификатом на IP).
func clientConnectParams(publicURL string) (addr, tlsFlags string, err error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "", "", fmt.Errorf("parse public url: %w", err)
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("public url without host: %q", publicURL)
	}
	port := u.Port()
	switch u.Scheme {
	case "https":
		if port == "" {
			port = "443"
		}
		tlsFlags = "-tls"
		if net.ParseIP(u.Hostname()) != nil {
			tlsFlags = "-tls -tls-insecure"
		}
	case "http", "":
		if port == "" {
			port = "80"
		}
	default:
		return "", "", fmt.Errorf("unsupported public url scheme: %q", u.Scheme)
	}
	return net.JoinHostPort(u.Hostname(), port), tlsFlags, nil
}

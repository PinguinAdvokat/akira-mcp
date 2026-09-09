-- OAuth-клиенты (dynamic registration, RFC 7591): публичические
-- клиенты без секретов, аутентификация обмена — client_id + PKCE.
CREATE TABLE oauth_clients (
    client_id     text PRIMARY KEY,
    client_name   text NOT NULL DEFAULT '',
    redirect_uris text[] NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Одноразовые коды авторизации: хранится только sha256-хеш.
-- Запись удаляется при первом обмене (одноразовость).
CREATE TABLE oauth_codes (
    code_hash    text PRIMARY KEY,
    user_id      text NOT NULL,
    client_id    text NOT NULL,
    redirect_uri text NOT NULL,
    scope        text NOT NULL DEFAULT '',
    code_challenge text NOT NULL DEFAULT '',
    code_challenge_method text NOT NULL DEFAULT '',
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

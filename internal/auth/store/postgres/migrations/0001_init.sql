-- Пользователи. connect_key назначается после подтверждения email
-- и глобально уникален; до верификации — NULL.
CREATE TABLE users (
    user_id            text PRIMARY KEY,
    username           text NOT NULL UNIQUE,
    email              text NOT NULL UNIQUE,
    password_hash      bytea NOT NULL,
    connect_key        text UNIQUE,
    email_verified_at  timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now()
);

-- Refresh-токены: хранится только sha256-хеш.
CREATE TABLE refresh_tokens (
    token_hash  text PRIMARY KEY,
    user_id     text NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Токены подтверждения email: одноразовые, активный токен один
-- на пользователя (user_id уникален).
CREATE TABLE email_verifications (
    token_hash  text PRIMARY KEY,
    user_id     text NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

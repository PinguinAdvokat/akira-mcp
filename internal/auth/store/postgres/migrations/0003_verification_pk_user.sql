-- PK email_verifications переносится с token_hash на user_id.
-- Активный код один на пользователя (user_id и так был UNIQUE), а вот
-- token_hash глобальной уникальности не требует: два пользователя могут
-- получить одинаковый 6-значный код, и с PK на token_hash второй
-- INSERT падал с unique_violation, хотя lookup всегда идёт по user_id.
ALTER TABLE email_verifications DROP CONSTRAINT email_verifications_pkey;
ALTER TABLE email_verifications DROP CONSTRAINT email_verifications_user_id_key;
ALTER TABLE email_verifications ADD PRIMARY KEY (user_id);

-- Под очистку протухших записей при старте (purgeExpired).
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
CREATE INDEX IF NOT EXISTS email_verifications_expires_at_idx ON email_verifications (expires_at);

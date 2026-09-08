-- Счётчик неверных вводов кода подтверждения (защита от перебора:
-- после authstore.MaxVerificationAttempts неудачных попыток код
-- перестаёт приниматься, нужен повторный resend).
ALTER TABLE email_verifications ADD COLUMN attempts int NOT NULL DEFAULT 0;

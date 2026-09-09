package authstorepostgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	authstore "github.com/PinguinAdvokat/akira-mcp/internal/auth/store"
)

// SaveOAuthClient сохраняет OAuth-клиента (dynamic registration).
func (s *Store) SaveOAuthClient(ctx context.Context, client authstore.OAuthClient) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at)
		 VALUES ($1, $2, $3, $4)`,
		client.ClientID, client.ClientName, client.RedirectURIs, client.CreatedAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// GetOAuthClient ищет OAuth-клиента по client_id.
func (s *Store) GetOAuthClient(ctx context.Context, clientID string) (authstore.OAuthClient, error) {
	var client authstore.OAuthClient
	err := s.pool.QueryRow(ctx,
		`SELECT client_id, client_name, redirect_uris, created_at
		 FROM oauth_clients WHERE client_id = $1`, clientID,
	).Scan(&client.ClientID, &client.ClientName, &client.RedirectURIs, &client.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return authstore.OAuthClient{}, authstore.ErrOAuthClientNotFound
	}
	if err != nil {
		return authstore.OAuthClient{}, err
	}
	return client, nil
}

// SaveOAuthCode сохраняет код авторизации.
func (s *Store) SaveOAuthCode(ctx context.Context, code authstore.OAuthCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_codes
		   (code_hash, user_id, client_id, redirect_uri, scope,
		    code_challenge, code_challenge_method, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		code.CodeHash, code.UserID, code.ClientID, code.RedirectURI, code.Scope,
		code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt, code.CreatedAt)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// ConsumeOAuthCode атомарно потребляет код: DELETE … RETURNING забирает
// запись ровно у одного конкурентного вызова (одноразовость без
// транзакции — одно выражение). Истёкший код не потребляется.
// Побочный эффект — копить в oauth_codes протухшие записи: их чистит
// purgeExpired при старте и последующие INSERT'ы не конфликтуют.
func (s *Store) ConsumeOAuthCode(ctx context.Context, codeHash string) (authstore.OAuthCode, error) {
	var code authstore.OAuthCode
	err := s.pool.QueryRow(ctx,
		`DELETE FROM oauth_codes WHERE code_hash = $1 AND expires_at > now()
		 RETURNING code_hash, user_id, client_id, redirect_uri, scope,
		           code_challenge, code_challenge_method, expires_at, created_at`,
		codeHash,
	).Scan(&code.CodeHash, &code.UserID, &code.ClientID, &code.RedirectURI, &code.Scope,
		&code.CodeChallenge, &code.CodeChallengeMethod, &code.ExpiresAt, &code.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return authstore.OAuthCode{}, authstore.ErrOAuthCodeNotFound
	}
	if err != nil {
		return authstore.OAuthCode{}, err
	}
	return code, nil
}

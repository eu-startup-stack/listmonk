package migrations

import (
	"log"

	"github.com/jmoiron/sqlx"
	"github.com/knadh/koanf/v2"
	"github.com/knadh/stuffbin"
)

func V6_3_0(db *sqlx.DB, fs stuffbin.FileSystem, ko *koanf.Koanf, lo *log.Logger) error {
	// Add the security.authentik settings row for existing installations.
	// Idempotent: ON CONFLICT DO NOTHING.
	if _, err := db.Exec(`
		INSERT INTO settings (key, value) VALUES
			('security.authentik', '{"enabled": false, "trusted_ips": [], "trusted_secret": "", "group_prefix": "listmonk"}')
		ON CONFLICT (key) DO NOTHING
	`); err != nil {
		return err
	}

	return nil
}

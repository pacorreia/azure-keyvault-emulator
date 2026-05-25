//go:build postgres

package sqlstore

import (
	"database/sql"

	_ "github.com/lib/pq" // register postgres driver
)

// OpenPostgres opens a Postgres database using the given DSN.
func OpenPostgres(dsn string) (*sql.DB, error) {
	return sql.Open("postgres", dsn)
}

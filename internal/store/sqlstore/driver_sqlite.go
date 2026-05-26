package sqlstore

import (
	"database/sql"

	_ "modernc.org/sqlite" // register sqlite driver
)

// OpenSQLite opens (or creates) an SQLite database at the given path.
// Use ":memory:" for an in-memory database.
func OpenSQLite(path string) (*sql.DB, error) {
	return sql.Open("sqlite", path)
}

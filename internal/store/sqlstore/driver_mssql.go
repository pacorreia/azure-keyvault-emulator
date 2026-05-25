//go:build mssql

package sqlstore

import (
	"database/sql"

	_ "github.com/microsoft/go-mssqldb" // register mssql driver
)

// OpenMSSQL opens a SQL Server database using the given DSN.
func OpenMSSQL(dsn string) (*sql.DB, error) {
	return sql.Open("sqlserver", dsn)
}

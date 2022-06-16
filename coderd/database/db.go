// Package database connects to external services for stateful storage.
//
// Query functions are generated using sqlc.
//
// To modify the database schema:
// 1. Add a new migration using "create_migration.sh" in database/migrations/
// 2. Run "make coderd/database/generate" in the root to generate models.
// 3. Add/Edit queries in "query.sql" and run "make coderd/database/generate" to create Go code.
package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

var SystemUserID uuid.UUID = uuid.MustParse("11111111-1111-1111-1111-111111111111")

// Store contains all queryable database functions.
// It extends the generated interface to add transaction support.
type Store interface {
	querier

	InTx(func(Store) error) error
}

// DBTX represents a database connection or transaction.
type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

// New creates a new database store using a SQL database connection.
func New(sdb *sql.DB) Store {
	return &sqlQuerier{
		db:  sdb,
		sdb: sdb,
	}
}

type sqlQuerier struct {
	sdb *sql.DB
	db  DBTX
}

// InTx performs database operations inside a transaction.
func (q *sqlQuerier) InTx(function func(Store) error) error {
	if q.sdb == nil {
		return nil
	}
	transaction, err := q.sdb.Begin()
	if err != nil {
		return xerrors.Errorf("begin transaction: %w", err)
	}
	defer func() {
		rerr := transaction.Rollback()
		if rerr == nil || errors.Is(rerr, sql.ErrTxDone) {
			// no need to do anything, tx committed successfully
			return
		}
		// couldn't roll back for some reason, extend returned error
		err = xerrors.Errorf("defer (%s): %w", rerr.Error(), err)
	}()
	err = function(&sqlQuerier{db: transaction})
	if err != nil {
		return xerrors.Errorf("execute transaction: %w", err)
	}
	err = transaction.Commit()
	if err != nil {
		return xerrors.Errorf("commit transaction: %w", err)
	}
	return nil
}

// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
)

//
//	sessions table schema:
//
//	id              INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
//	email           TEXT    NOT NULL
//	email_canonical TEXT    NOT NULL UNIQUE
//	duration        INTEGER NOT NULL
//	created_at      INTEGER NOT NULL             DEFAULT CURRENT_TIMESTAMP
//

// Queries used by the SQLite session backing.
const (
	newSessionQuery = `
		INSERT INTO sessions
		(email, email_canonical, duration)
		VALUES
		(?, ?, min(?, ?))
	`
	hasSessionQuery = `
		SELECT id
		FROM sessions
		WHERE email_canonical=?
		AND datetime(
			strftime('%s', created_at) + duration, 'unixepoch'
		) > datetime('now')
	`
)

// SQLiteBacking implements that SessionBacking interface, and allows for
// manipulating sessions stored in an SQLite3 database.
type SQLiteBacking struct {
	DB             *sql.DB
	newSessionStmt *sql.Stmt
	hasSessionStmt *sql.Stmt
}

// Open implements the Open method of the SessionBacking interface.
func (b *SQLiteBacking) Open(location string) (err error) {
	b.DB, err = sql.Open("sqlite3", location)
	if err != nil {
		return err
	}
	return b.DB.Ping()
}

// Close implements the Close method of the SessionBacking interface.
func (b *SQLiteBacking) Close() (err error) {
	if b.DB != nil {
		err = b.DB.Close()
		b.DB = nil
	}
	if b.newSessionStmt != nil {
		err = b.newSessionStmt.Close()
		b.newSessionStmt = nil
	}
	if b.hasSessionStmt != nil {
		err = b.hasSessionStmt.Close()
		b.hasSessionStmt = nil
	}

	return
}

// NewSession implements the NewSession method of the SessionBacking interface.
func (b *SQLiteBacking) NewSession(email, id string) (err error) {
	if b.DB == nil {
		err = errors.New(errSessionBackingNotOpened)
		return
	}
	if b.newSessionStmt == nil {
		b.newSessionStmt, err = b.DB.Prepare(newSessionQuery)
		if err != nil {
			return
		}
	}

	result, err := b.newSessionStmt.Exec(email, id)
	if err != nil {
		return
	}

	n, err := result.RowsAffected()
	if err != nil {
		return
	}
	if n == 0 {
		err = errors.New(errNewSessionNoRowsAffected)
		return
	}

	return
}

// HasSession implements the HasSession method of the SessionBacking interface.
func (b *SQLiteBacking) HasSession(email string) (hasSession bool, err error) {
	if b.DB == nil {
		err = errors.New(errSessionBackingNotOpened)
		return
	}
	if b.hasSessionStmt == nil {
		b.hasSessionStmt, err = b.DB.Prepare(hasSessionQuery)
		if err != nil {
			return
		}
	}

	var id int
	err = b.hasSessionStmt.QueryRow(email).Scan(&id)
	switch err {
	case nil:
		hasSession = true
	case sql.ErrNoRows:
		err = nil
	}
	return
}

// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

// SessionMaxDuration is the maximum duration, in seconds, that a session can
// be valid for.
const SessionMaxDuration = 86400

// Error messages.
const (
	errSessionBackingNotOpened  = "session backing has not been opened."
	errSessionBackingUndefined  = "session backing is undefined."
	errNewSessionNoRowsAffected = "failed to create a new session: no rows affected"
)

// SessionBacking is the interface used by all session backings.
type SessionBacking interface {
	Open(string) error
	Close() error
	NewSession(string, string) error
	HasSession(string) (bool, error)
}

var sessionBacking SessionBacking

// SetSessionBacking uses the supplied session backing.
func SetSessionBacking(backing SessionBacking) {
	sessionBacking = backing
}

// CloseSessionBacking closes the session backing.
func CloseSessionBacking() {
	if sessionBacking != nil {
		sessionBacking.Close()
	}
}

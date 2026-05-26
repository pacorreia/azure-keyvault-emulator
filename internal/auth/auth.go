package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const sessionTTL = 24 * time.Hour

type Role string

const (
	RoleAdmin       Role = "admin"
	RoleContributor Role = "contributor"
	RoleReader      Role = "reader"
)

var (
	ErrAlreadyInitialized = errors.New("auth service already initialized")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         Role
	CreatedAt    int64
}

type Session struct {
	Token     string
	UserID    string
	Username  string
	Role      Role
	ExpiresAt int64
}

type Service struct {
	db         *sql.DB
	sessionsMu sync.RWMutex
	sessions   map[string]*Session
}

func Open(path string) (*Service, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}

	service := &Service{
		db:       db,
		sessions: make(map[string]*Session),
	}

	if err := service.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return service, nil
}

func NewMemory() (*Service, error) {
	return Open(":memory:")
}

func (s *Service) IsInitialized() (bool, error) {
	var exists bool
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1
			FROM users
			WHERE role = ?
			LIMIT 1
		)
	`, RoleAdmin).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (s *Service) Setup(username, password string) (*User, error) {
	if err := validateCredentialsInput(username, password); err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var exists bool
	if err := tx.QueryRow(`
		SELECT EXISTS(
			SELECT 1
			FROM users
			WHERE role = ?
			LIMIT 1
		)
	`, RoleAdmin).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrAlreadyInitialized
	}

	user, err := newUser(username, password, RoleAdmin)
	if err != nil {
		return nil, err
	}
	if err := insertUser(tx, user); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return cloneUser(user), nil
}

func (s *Service) CreateUser(username, password string, role Role) (*User, error) {
	if err := validateCredentialsInput(username, password); err != nil {
		return nil, err
	}
	if !role.Valid() {
		return nil, fmt.Errorf("invalid role %q", role)
	}

	user, err := newUser(username, password, role)
	if err != nil {
		return nil, err
	}
	if err := insertUser(s.db, user); err != nil {
		return nil, err
	}

	return cloneUser(user), nil
}

func (s *Service) Login(username, password string) (*Session, error) {
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.getUserByUsername(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	token, err := generateHex(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Token:     token,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(sessionTTL).Unix(),
	}

	s.sessionsMu.Lock()
	s.sessions[token] = session
	s.sessionsMu.Unlock()

	return cloneSession(session), nil
}

func (s *Service) ValidateSession(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[token]
	s.sessionsMu.RUnlock()
	if !ok {
		return nil, false
	}

	if time.Now().Unix() >= session.ExpiresAt {
		s.sessionsMu.Lock()
		if current, ok := s.sessions[token]; ok && time.Now().Unix() >= current.ExpiresAt {
			delete(s.sessions, token)
		}
		s.sessionsMu.Unlock()
		return nil, false
	}

	return cloneSession(session), true
}

func (s *Service) Logout(token string) {
	s.sessionsMu.Lock()
	delete(s.sessions, token)
	s.sessionsMu.Unlock()
}

func (s *Service) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`
		SELECT id, username, password_hash, role, created_at
		FROM users
		ORDER BY created_at ASC, username ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (s *Service) DeleteUser(id string) error {
	if id == "" {
		return errors.New("user id is required")
	}

	if _, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}

	s.sessionsMu.Lock()
	for token, session := range s.sessions {
		if session.UserID == id {
			delete(s.sessions, token)
		}
	}
	s.sessionsMu.Unlock()

	return nil
}

func (s *Service) GetConfig(key string) (string, bool) {
	if key == "" {
		return "", false
	}

	var value string
	err := s.db.QueryRow(`SELECT value FROM config WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", false
	}
	return value, true
}

func (s *Service) SetConfig(key, value string) error {
	if key == "" {
		return errors.New("config key is required")
	}

	_, err := s.db.Exec(`
		INSERT INTO config(key, value)
		VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

func (s *Service) Close() error {
	s.sessionsMu.Lock()
	s.sessions = map[string]*Session{}
	s.sessionsMu.Unlock()
	return s.db.Close()
}

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleContributor, RoleReader:
		return true
	default:
		return false
	}
}

func (s *Service) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		// Enforce that only one admin user can exist, even under concurrent setup attempts.
		`CREATE UNIQUE INDEX IF NOT EXISTS users_single_admin ON users(role) WHERE role = 'admin'`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}

	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}

	return s.db.Ping()
}

func (s *Service) getUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(`
		SELECT id, username, password_hash, role, created_at
		FROM users
		WHERE username = ?
	`, username)
	return scanUser(row)
}

func newUser(username, password string, role Role) (*User, error) {
	id, err := generateHex(16)
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:           id,
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		CreatedAt:    time.Now().Unix(),
	}, nil
}

func insertUser(exec interface {
	Exec(query string, args ...any) (sql.Result, error)
}, user *User) error {
	_, err := exec.Exec(`
		INSERT INTO users(id, username, password_hash, role, created_at)
		VALUES(?, ?, ?, ?, ?)
	`, user.ID, user.Username, user.PasswordHash, user.Role, user.CreatedAt)
	return err
}

func validateCredentialsInput(username, password string) error {
	if username == "" {
		return errors.New("username is required")
	}
	if password == "" {
		return errors.New("password is required")
	}
	return nil
}

func scanUser(scanner interface {
	Scan(dest ...any) error
}) (*User, error) {
	user := &User{}
	var role string
	if err := scanner.Scan(&user.ID, &user.Username, &user.PasswordHash, &role, &user.CreatedAt); err != nil {
		return nil, err
	}
	user.Role = Role(role)
	return user, nil
}

func cloneUser(user *User) *User {
	if user == nil {
		return nil
	}
	clone := *user
	return &clone
}

func cloneSession(session *Session) *Session {
	if session == nil {
		return nil
	}
	clone := *session
	return &clone
}

func generateHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

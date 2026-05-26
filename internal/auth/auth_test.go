package auth

import (
	"errors"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := svc.Close(); err != nil {
			t.Errorf("close auth service: %v", err)
		}
	})
	return svc
}

func mustSetup(t *testing.T, svc *Service) *User {
	t.Helper()
	user, err := svc.Setup("admin", "password123")
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func mustCreateUser(t *testing.T, svc *Service, username string, role Role) *User {
	t.Helper()
	user, err := svc.CreateUser(username, "password123", role)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func mustLogin(t *testing.T, svc *Service, username, password string) *Session {
	t.Helper()
	session, err := svc.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestSetupFlow(t *testing.T) {
	svc := newTestService(t)

	initialized, err := svc.IsInitialized()
	if err != nil {
		t.Fatal(err)
	}
	if initialized {
		t.Fatal("expected service to start uninitialized")
	}

	user := mustSetup(t, svc)
	if user.Role != RoleAdmin {
		t.Fatalf("expected admin role, got %q", user.Role)
	}
	if user.ID == "" {
		t.Fatal("expected user id")
	}
	if _, err := bcrypt.Cost([]byte(user.PasswordHash)); err != nil {
		t.Fatalf("expected bcrypt password hash: %v", err)
	}
	if !utf8.ValidString(user.ID) {
		t.Fatalf("expected valid user id %q", user.ID)
	}

	initialized, err = svc.IsInitialized()
	if err != nil {
		t.Fatal(err)
	}
	if !initialized {
		t.Fatal("expected initialized service after setup")
	}

	if _, err := svc.Setup("admin2", "password456"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestLoginSuccessAndFailure(t *testing.T) {
	svc := newTestService(t)
	admin := mustSetup(t, svc)

	session := mustLogin(t, svc, "admin", "password123")
	if session.UserID != admin.ID || session.Username != admin.Username || session.Role != RoleAdmin {
		t.Fatalf("unexpected session %+v", session)
	}
	if session.Token == "" {
		t.Fatal("expected session token")
	}
	if session.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("expected future expiry, got %d", session.ExpiresAt)
	}

	if _, err := svc.Login("admin", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for wrong password, got %v", err)
	}
	if _, err := svc.Login("missing", "password123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for unknown user, got %v", err)
	}
}

func TestValidateSessionAndExpiry(t *testing.T) {
	svc := newTestService(t)
	mustSetup(t, svc)

	session := mustLogin(t, svc, "admin", "password123")
	validated, ok := svc.ValidateSession(session.Token)
	if !ok {
		t.Fatal("expected valid session")
	}
	if validated.Token != session.Token || validated.UserID != session.UserID {
		t.Fatalf("unexpected validated session %+v", validated)
	}

	svc.sessionsMu.Lock()
	svc.sessions[session.Token].ExpiresAt = time.Now().Add(-time.Minute).Unix()
	svc.sessionsMu.Unlock()

	if _, ok := svc.ValidateSession(session.Token); ok {
		t.Fatal("expected expired session to be rejected")
	}
	svc.sessionsMu.RLock()
	_, exists := svc.sessions[session.Token]
	svc.sessionsMu.RUnlock()
	if exists {
		t.Fatal("expected expired session to be removed")
	}
}

func TestLogout(t *testing.T) {
	svc := newTestService(t)
	mustSetup(t, svc)

	session := mustLogin(t, svc, "admin", "password123")
	svc.Logout(session.Token)

	if _, ok := svc.ValidateSession(session.Token); ok {
		t.Fatal("expected logged out session to be invalid")
	}
}

func TestListUsersDeleteUserAndCreateUser(t *testing.T) {
	svc := newTestService(t)
	admin := mustSetup(t, svc)
	contributor := mustCreateUser(t, svc, "contributor", RoleContributor)
	reader := mustCreateUser(t, svc, "reader", RoleReader)
	readerSession := mustLogin(t, svc, "reader", "password123")

	users, err := svc.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(users))
	}

	roles := map[string]Role{}
	for _, user := range users {
		roles[user.Username] = user.Role
	}
	if roles[admin.Username] != RoleAdmin || roles[contributor.Username] != RoleContributor || roles[reader.Username] != RoleReader {
		t.Fatalf("unexpected roles %#v", roles)
	}

	if err := svc.DeleteUser(reader.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.ValidateSession(readerSession.Token); ok {
		t.Fatal("expected deleted user's sessions to be removed")
	}

	users, err = svc.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users after delete, got %d", len(users))
	}
	for _, user := range users {
		if user.ID == reader.ID {
			t.Fatal("deleted user still listed")
		}
	}
}

func TestGetConfigSetConfig(t *testing.T) {
	svc := newTestService(t)

	if value, ok := svc.GetConfig("missing"); ok || value != "" {
		t.Fatalf("expected missing config, got %q %v", value, ok)
	}

	if err := svc.SetConfig("issuer", "https://example.test"); err != nil {
		t.Fatal(err)
	}
	if value, ok := svc.GetConfig("issuer"); !ok || value != "https://example.test" {
		t.Fatalf("unexpected config value %q %v", value, ok)
	}

	if err := svc.SetConfig("issuer", "https://updated.test"); err != nil {
		t.Fatal(err)
	}
	if value, ok := svc.GetConfig("issuer"); !ok || value != "https://updated.test" {
		t.Fatalf("unexpected updated config value %q %v", value, ok)
	}
}

func TestIsInitialized(t *testing.T) {
	svc := newTestService(t)

	initialized, err := svc.IsInitialized()
	if err != nil {
		t.Fatal(err)
	}
	if initialized {
		t.Fatal("expected no admin users initially")
	}

	if _, err := svc.CreateUser("reader", "password123", RoleReader); err != nil {
		t.Fatal(err)
	}
	initialized, err = svc.IsInitialized()
	if err != nil {
		t.Fatal(err)
	}
	if initialized {
		t.Fatal("expected non-admin users to not initialize service")
	}

	if _, err := svc.Setup("admin", "password123"); err != nil {
		t.Fatal(err)
	}
	initialized, err = svc.IsInitialized()
	if err != nil {
		t.Fatal(err)
	}
	if !initialized {
		t.Fatal("expected admin setup to initialize service")
	}
}

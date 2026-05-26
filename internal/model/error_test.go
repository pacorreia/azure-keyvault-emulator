package model

import "testing"

func TestNewKeyVaultError(t *testing.T) {
	err := NewKeyVaultError("BadParameter", "bad")
	if err.Error.Code != "BadParameter" || err.Error.Message != "bad" {
		t.Fatalf("unexpected error %+v", err)
	}
}

package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"testing"

	kvcrypto "github.com/pacorreia/azure-keyvault-emulator/internal/crypto"
	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func mustStoreRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(crand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustStoreECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaImportRequest(t *testing.T) model.ImportKeyRequest {
	t.Helper()
	key := mustStoreRSAKey(t, 1024)
	jwk := kvcrypto.RSAToJWK("", "RSA", nil, &key.PublicKey)
	jwk.D = kvcrypto.EncodeBase64URL(key.D.Bytes())
	jwk.P = kvcrypto.EncodeBase64URL(key.Primes[0].Bytes())
	jwk.Q = kvcrypto.EncodeBase64URL(key.Primes[1].Bytes())
	return model.ImportKeyRequest{Key: jwk}
}

func ecImportRequest(t *testing.T) model.ImportKeyRequest {
	t.Helper()
	key := mustStoreECDSAKey(t, elliptic.P256())
	jwk := kvcrypto.ECDSAToJWK("", "EC", nil, "P-256", &key.PublicKey)
	jwk.D = kvcrypto.EncodeBase64URL(key.D.Bytes())
	return model.ImportKeyRequest{Key: jwk}
}

func TestKeyLifecycle(t *testing.T) {
	t.Run("CreateKey", func(t *testing.T) {
		s := New()
		if _, err := s.CreateKey("", model.CreateKeyRequest{Kty: "RSA"}); err == nil {
			t.Fatal("expected empty name error")
		}
		if _, err := s.CreateKey("name", model.CreateKeyRequest{}); err == nil {
			t.Fatal("expected empty kty error")
		}
		rsaRec, err := s.CreateKey("rsa", model.CreateKeyRequest{Kty: "RSA", KeySize: 1024})
		if err != nil {
			t.Fatal(err)
		}
		if rsaRec.Key.Kty != "RSA" || len(rsaRec.Key.KeyOps) == 0 {
			t.Fatalf("unexpected rsa record %+v", rsaRec)
		}
		ecRec, err := s.CreateKey("ec", model.CreateKeyRequest{Kty: "EC", Crv: "P-256"})
		if err != nil || ecRec.Key.Crv != "P-256" {
			t.Fatalf("unexpected ec record %+v %v", ecRec, err)
		}
		octRec, err := s.CreateKey("oct", model.CreateKeyRequest{Kty: "oct", KeySize: 128})
		if err != nil || octRec.Key.Kty != "oct" {
			t.Fatalf("unexpected oct record %+v %v", octRec, err)
		}
		if _, err := s.CreateKey("bad", model.CreateKeyRequest{Kty: "bad"}); err == nil {
			t.Fatal("expected invalid kty error")
		}
		_, _ = s.DeleteKey("rsa")
		if _, err := s.CreateKey("rsa", model.CreateKeyRequest{Kty: "RSA"}); err == nil {
			t.Fatal("expected deleted conflict")
		}
	})

	t.Run("ImportKey", func(t *testing.T) {
		s := New()
		rsaRec, err := s.ImportKey("rsa", rsaImportRequest(t))
		if err != nil || rsaRec.Key.Kty != "RSA" {
			t.Fatalf("unexpected rsa import %+v %v", rsaRec, err)
		}
		ecRec, err := s.ImportKey("ec", ecImportRequest(t))
		if err != nil || ecRec.Key.Crv != "P-256" {
			t.Fatalf("unexpected ec import %+v %v", ecRec, err)
		}
		octRec, err := s.ImportKey("oct", model.ImportKeyRequest{Key: model.JSONWebKey{Kty: "oct", K: kvcrypto.EncodeBase64URL([]byte("0123456789abcdef"))}})
		if err != nil || octRec.Key.Kty != "oct" {
			t.Fatalf("unexpected oct import %+v %v", octRec, err)
		}
		if _, err := s.ImportKey("", rsaImportRequest(t)); err == nil {
			t.Fatal("expected empty name error")
		}
		if _, err := s.ImportKey("name", model.ImportKeyRequest{}); err == nil {
			t.Fatal("expected empty kty error")
		}
		if _, err := s.ImportKey("bad", model.ImportKeyRequest{Key: model.JSONWebKey{Kty: "RSA"}}); err == nil {
			t.Fatal("expected import error")
		}
		_, _ = s.DeleteKey("rsa")
		if _, err := s.ImportKey("rsa", rsaImportRequest(t)); err == nil {
			t.Fatal("expected deleted conflict")
		}
	})

	t.Run("GetAndList", func(t *testing.T) {
		s := New()
		first := mustCreateKey(t, s, "name", "RSA")
		second, err := s.ImportKey("name", rsaImportRequest(t))
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.GetKey("name", "")
		if err != nil || got.Version != second.Version {
			t.Fatalf("unexpected latest %+v %v", got, err)
		}
		got, err = s.GetKey("name", first.Version)
		if err != nil || got.Version != first.Version {
			t.Fatalf("unexpected version %+v %v", got, err)
		}
		if _, err := s.GetKey("missing", ""); err == nil {
			t.Fatal("expected not found")
		}
		list, next, err := s.ListKeys(10, "")
		if err != nil || len(list) != 1 || next != nil {
			t.Fatalf("unexpected key list %v %v %v", list, next, err)
		}
		mustCreateKey(t, s, "another", "RSA")
		mustCreateKey(t, s, "third", "RSA")
		page, next, err := s.ListKeys(2, "")
		if err != nil || len(page) != 2 || next == nil {
			t.Fatalf("unexpected key page %v %v %v", page, next, err)
		}
		versions, next, err := s.ListKeyVersions("name", 10, "")
		if err != nil || len(versions) != 2 || next != nil {
			t.Fatalf("unexpected version list %v %v %v", versions, next, err)
		}
		if _, _, err := s.ListKeyVersions("missing", 10, ""); err == nil {
			t.Fatal("expected list version not found")
		}
	})

	t.Run("UpdateKey", func(t *testing.T) {
		s := New()
		rec := mustCreateKey(t, s, "name", "RSA")
		updated, err := s.UpdateKey("name", rec.Version, model.UpdateKeyRequest{
			Tags:       map[string]string{"env": "test"},
			KeyOps:     []string{"sign"},
			Attributes: &model.Attributes{Enabled: boolPtr(false)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated.Tags["env"] != "test" || len(updated.Key.KeyOps) != 1 || updated.Attributes.Enabled == nil || *updated.Attributes.Enabled {
			t.Fatalf("unexpected update %+v", updated)
		}
		if _, err := s.UpdateKey("name", "missing", model.UpdateKeyRequest{}); err == nil {
			t.Fatal("expected update not found")
		}
	})

	t.Run("DeleteAndRecover", func(t *testing.T) {
		s := New()
		mustCreateKey(t, s, "name", "RSA")
		deleted, err := s.DeleteKey("name")
		if err != nil || deleted.RecoveryID == "" {
			t.Fatalf("unexpected delete %+v %v", deleted, err)
		}
		if _, err := s.DeleteKey("missing"); err == nil {
			t.Fatal("expected delete not found")
		}
		if _, err := s.GetDeletedKey("missing"); err == nil {
			t.Fatal("expected get deleted not found")
		}
		got, err := s.GetDeletedKey("name")
		if err != nil || got.Name != "name" {
			t.Fatalf("unexpected deleted key %+v %v", got, err)
		}
		list, next, err := s.ListDeletedKeys(10, "")
		if err != nil || len(list) != 1 || next != nil {
			t.Fatalf("unexpected deleted key list %v %v %v", list, next, err)
		}
		recovered, err := s.RecoverDeletedKey("name")
		if err != nil || recovered.Name != "name" {
			t.Fatalf("unexpected recover %+v %v", recovered, err)
		}
		if _, err := s.RecoverDeletedKey("missing"); err == nil {
			t.Fatal("expected recover not found")
		}
		s.deletedKeys["name"] = &deletedKeyEntry{entry: &keyEntry{versions: []*keyVersion{{record: recovered}}}}
		if _, err := s.RecoverDeletedKey("name"); err == nil {
			t.Fatal("expected recover conflict")
		}
		if err := s.PurgeDeletedKey("name"); err != nil {
			t.Fatal(err)
		}
		if err := s.PurgeDeletedKey("name"); err == nil {
			t.Fatal("expected purge not found")
		}
	})

	t.Run("EncryptDecrypt", func(t *testing.T) {
		s := New()
		rec := mustCreateKey(t, s, "rsa", "RSA")
		ciphertext, iv, err := s.Encrypt("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: kvcrypto.EncodeBase64URL([]byte("hello"))})
		if err != nil || iv != "" {
			t.Fatalf("unexpected encrypt %q %q %v", ciphertext, iv, err)
		}
		plaintext, _, err := s.Decrypt("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: ciphertext})
		if err != nil || string(mustDecodeStore(t, plaintext)) != "hello" {
			t.Fatalf("unexpected decrypt %q %v", plaintext, err)
		}
		if _, _, err := s.Encrypt("missing", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: "aGVsbG8"}); err == nil {
			t.Fatal("expected key not found")
		}
		if _, _, err := s.Encrypt("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: "***"}); err == nil {
			t.Fatal("expected bad base64")
		}
		if _, _, err := s.Decrypt("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: "***"}); err == nil {
			t.Fatal("expected bad base64 decrypt")
		}
	})

	t.Run("SignVerify", func(t *testing.T) {
		s := New()
		rsaRec := mustCreateKey(t, s, "rsa", "RSA")
		digest := kvcrypto.EncodeBase64URL(kvcrypto.DigestForAlg("RS256", []byte("hello")))
		sig, err := s.Sign("rsa", rsaRec.Version, model.SignRequest{Alg: "RS256", Value: digest})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := s.Verify("rsa", rsaRec.Version, model.VerifyRequest{Alg: "RS256", Digest: digest, Value: sig})
		if err != nil || !ok {
			t.Fatalf("unexpected rsa verify %v %v", ok, err)
		}
		ecRec, err := s.ImportKey("ec", ecImportRequest(t))
		if err != nil {
			t.Fatal(err)
		}
		digest = kvcrypto.EncodeBase64URL(kvcrypto.DigestForAlg("ES256", []byte("hello")))
		sig, err = s.Sign("ec", ecRec.Version, model.SignRequest{Alg: "ES256", Value: digest})
		if err != nil {
			t.Fatal(err)
		}
		ok, err = s.Verify("ec", ecRec.Version, model.VerifyRequest{Alg: "ES256", Digest: digest, Value: sig})
		if err != nil || !ok {
			t.Fatalf("unexpected ec verify %v %v", ok, err)
		}
		if _, err := s.Sign("missing", rsaRec.Version, model.SignRequest{Alg: "RS256", Value: digest}); err == nil {
			t.Fatal("expected sign not found")
		}
		if _, err := s.Sign("rsa", rsaRec.Version, model.SignRequest{Alg: "RS256", Value: "***"}); err == nil {
			t.Fatal("expected bad digest base64")
		}
		if _, err := s.Verify("missing", rsaRec.Version, model.VerifyRequest{Alg: "RS256", Digest: digest, Value: sig}); err == nil {
			t.Fatal("expected verify not found")
		}
		if _, err := s.Verify("rsa", rsaRec.Version, model.VerifyRequest{Alg: "RS256", Digest: "***", Value: sig}); err == nil {
			t.Fatal("expected bad verify digest")
		}
		if _, err := s.Verify("rsa", rsaRec.Version, model.VerifyRequest{Alg: "RS256", Digest: digest, Value: "***"}); err == nil {
			t.Fatal("expected bad verify signature")
		}
	})

	t.Run("WrapUnwrap", func(t *testing.T) {
		s := New()
		rec := mustCreateKey(t, s, "rsa", "RSA")
		wrapped, err := s.WrapKey("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: kvcrypto.EncodeBase64URL([]byte("12345678"))})
		if err != nil {
			t.Fatal(err)
		}
		unwrapped, err := s.UnwrapKey("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: wrapped})
		if err != nil || !bytes.Equal(mustDecodeStore(t, unwrapped), []byte("12345678")) {
			t.Fatalf("unexpected unwrap %q %v", unwrapped, err)
		}
		if _, err := s.WrapKey("missing", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: wrapped}); err == nil {
			t.Fatal("expected wrap not found")
		}
		if _, err := s.WrapKey("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: "***"}); err == nil {
			t.Fatal("expected wrap bad base64")
		}
		if _, err := s.UnwrapKey("missing", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: wrapped}); err == nil {
			t.Fatal("expected unwrap not found")
		}
		if _, err := s.UnwrapKey("rsa", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: "***"}); err == nil {
			t.Fatal("expected unwrap bad base64")
		}
	})

	t.Run("HelperBranches", func(t *testing.T) {
		if ops := defaultKeyOps("EC", nil); len(ops) != 2 || ops[0] != "sign" {
			t.Fatalf("unexpected ec ops %v", ops)
		}
		if ops := defaultKeyOps("oct", nil); len(ops) != 4 || ops[0] != "encrypt" {
			t.Fatalf("unexpected oct ops %v", ops)
		}
	})
}

func mustDecodeStore(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := kvcrypto.DecodeBase64URL(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestAdditionalKeyStoreCoverage(t *testing.T) {
	s := New()
	rec := mustCreateKey(t, s, "rsa2", "RSA")
	if _, _, err := s.Encrypt("rsa2", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: kvcrypto.EncodeBase64URL([]byte("hello")), IV: "***"}); err == nil {
		t.Fatal("expected bad encrypt iv")
	}
	if _, _, err := s.Encrypt("rsa2", rec.Version, model.EncryptRequest{Alg: "bad", Value: kvcrypto.EncodeBase64URL([]byte("hello"))}); err == nil {
		t.Fatal("expected invalid encrypt algorithm")
	}
	ciphertext, _, err := s.Encrypt("rsa2", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: kvcrypto.EncodeBase64URL([]byte("hello"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Decrypt("rsa2", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: ciphertext, IV: "***"}); err == nil {
		t.Fatal("expected bad decrypt iv")
	}
	if _, _, err := s.Decrypt("rsa2", rec.Version, model.EncryptRequest{Alg: "bad", Value: ciphertext}); err == nil {
		t.Fatal("expected invalid decrypt algorithm")
	}
	digest := kvcrypto.EncodeBase64URL(kvcrypto.DigestForAlg("RS256", []byte("hello")))
	if _, err := s.Sign("rsa2", rec.Version, model.SignRequest{Alg: "bad", Value: digest}); err == nil {
		t.Fatal("expected invalid sign algorithm")
	}
	sig, err := s.Sign("rsa2", rec.Version, model.SignRequest{Alg: "RS256", Value: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify("rsa2", rec.Version, model.VerifyRequest{Alg: "bad", Digest: digest, Value: sig}); err == nil {
		t.Fatal("expected invalid verify algorithm")
	}
	if _, err := s.WrapKey("rsa2", rec.Version, model.EncryptRequest{Alg: "bad", Value: kvcrypto.EncodeBase64URL([]byte("12345678"))}); err == nil {
		t.Fatal("expected invalid wrap algorithm")
	}
	wrapped, err := s.WrapKey("rsa2", rec.Version, model.EncryptRequest{Alg: "RSA-OAEP", Value: kvcrypto.EncodeBase64URL([]byte("12345678"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UnwrapKey("rsa2", rec.Version, model.EncryptRequest{Alg: "bad", Value: wrapped}); err == nil {
		t.Fatal("expected invalid unwrap algorithm")
	}
}

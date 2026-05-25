package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

func mustRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(crand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaPrivateJWK(key *rsa.PrivateKey) model.JSONWebKey {
	jwk := RSAToJWK("kid", "RSA", []string{"encrypt"}, &key.PublicKey)
	jwk.D = EncodeBase64URL(key.D.Bytes())
	jwk.P = EncodeBase64URL(key.Primes[0].Bytes())
	jwk.Q = EncodeBase64URL(key.Primes[1].Bytes())
	return jwk
}

func ecPrivateJWK(key *ecdsa.PrivateKey, crv string) model.JSONWebKey {
	jwk := ECDSAToJWK("kid", "EC", []string{"sign"}, crv, &key.PublicKey)
	jwk.D = EncodeBase64URL(padBytes(key.D.Bytes(), (key.Params().BitSize+7)/8))
	return jwk
}

func TestBase64URLRoundTrip(t *testing.T) {
	data := []byte("hello+/=")
	encoded := EncodeBase64URL(data)
	decoded, err := DecodeBase64URL(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatalf("decoded %q", decoded)
	}
	if _, err := DecodeBase64URL("!"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name string
		kty  string
		size int
		crv  string
	}{
		{name: "rsa", kty: "RSA", size: 1024},
		{name: "rsa-hsm", kty: "RSA-HSM", size: 1024},
		{name: "ec-p256", kty: "EC", crv: "P-256"},
		{name: "ec-p384", kty: "EC", crv: "P-384"},
		{name: "ec-p521", kty: "EC", crv: "P-521"},
		{name: "ec-hsm", kty: "EC-HSM", crv: "P-256"},
		{name: "oct-128", kty: "oct", size: 128},
		{name: "oct-256", kty: "oct", size: 256},
		{name: "oct-hsm", kty: "oct-HSM", size: 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material, jwk, err := GenerateKey(tt.kty, tt.size, tt.crv, "kid", []string{"op"})
			if err != nil {
				t.Fatal(err)
			}
			if jwk.Kty != tt.kty || jwk.Kid != "kid" {
				t.Fatalf("unexpected jwk: %+v", jwk)
			}
			switch tt.kty {
			case "RSA", "RSA-HSM":
				if material.RSA == nil || material.RSAPub == nil || jwk.N == "" || jwk.E == "" {
					t.Fatalf("unexpected rsa material: %+v %+v", material, jwk)
				}
			case "EC", "EC-HSM":
				if material.ECDSA == nil || material.ECDSAPub == nil || jwk.Crv != tt.crv || jwk.X == "" || jwk.Y == "" {
					t.Fatalf("unexpected ec material: %+v %+v", material, jwk)
				}
			case "oct", "oct-HSM":
				if len(material.AES) != tt.size/8 || jwk.K != "" {
					t.Fatalf("unexpected oct material: %+v %+v", material, jwk)
				}
			}
		})
	}
}

func TestGenerateKeyErrors(t *testing.T) {
	if _, _, err := GenerateKey("bogus", 0, "", "", nil); err == nil {
		t.Fatal("expected unsupported key type error")
	}
	if _, _, err := GenerateKey("EC", 0, "P-999", "", nil); err == nil {
		t.Fatal("expected unsupported curve error")
	}
	if _, _, err := GenerateKey("oct", 129, "", "", nil); err == nil {
		t.Fatal("expected invalid symmetric size error")
	}
	oldRSA := rsaGenerateKey
	rsaGenerateKey = func(_ io.Reader, _ int) (*rsa.PrivateKey, error) { return nil, errors.New("boom") }
	if _, _, err := GenerateKey("RSA", 1024, "", "", nil); err == nil {
		t.Fatal("expected rsa generator error")
	}
	rsaGenerateKey = oldRSA
	oldECDSA := ecdsaGenerateKey
	ecdsaGenerateKey = func(_ elliptic.Curve, _ io.Reader) (*ecdsa.PrivateKey, error) { return nil, errors.New("boom") }
	if _, _, err := GenerateKey("EC", 0, "P-256", "", nil); err == nil {
		t.Fatal("expected ecdsa generator error")
	}
	ecdsaGenerateKey = oldECDSA
	oldRead := randRead
	randRead = func(_ []byte) (int, error) { return 0, errors.New("boom") }
	if _, _, err := GenerateKey("oct", 128, "", "", nil); err == nil {
		t.Fatal("expected symmetric read error")
	}
	randRead = oldRead
}

func TestImportKey(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	ecKey := mustECDSAKey(t, elliptic.P256())
	sym := []byte("0123456789abcdef")

	tests := []struct {
		name  string
		jwk   model.JSONWebKey
		check func(t *testing.T, material KeyMaterial, out model.JSONWebKey)
	}{
		{
			name: "rsa-private",
			jwk:  rsaPrivateJWK(rsaKey),
			check: func(t *testing.T, material KeyMaterial, out model.JSONWebKey) {
				if material.RSA == nil || material.RSAPub == nil || out.N == "" || out.D != "" {
					t.Fatalf("unexpected rsa private import: %+v %+v", material, out)
				}
			},
		},
		{
			name: "rsa-public",
			jwk:  RSAToJWK("kid", "RSA", []string{"verify"}, &rsaKey.PublicKey),
			check: func(t *testing.T, material KeyMaterial, out model.JSONWebKey) {
				if material.RSA != nil || material.RSAPub == nil || out.N == "" {
					t.Fatalf("unexpected rsa public import: %+v %+v", material, out)
				}
			},
		},
		{
			name: "ec-private",
			jwk:  ecPrivateJWK(ecKey, "P-256"),
			check: func(t *testing.T, material KeyMaterial, out model.JSONWebKey) {
				if material.ECDSA == nil || material.ECDSAPub == nil || out.Crv != "P-256" {
					t.Fatalf("unexpected ec private import: %+v %+v", material, out)
				}
			},
		},
		{
			name: "ec-public",
			jwk:  ECDSAToJWK("kid", "EC", []string{"verify"}, "P-256", &ecKey.PublicKey),
			check: func(t *testing.T, material KeyMaterial, out model.JSONWebKey) {
				if material.ECDSA != nil || material.ECDSAPub == nil || out.Crv != "P-256" {
					t.Fatalf("unexpected ec public import: %+v %+v", material, out)
				}
			},
		},
		{
			name: "oct",
			jwk:  model.JSONWebKey{Kty: "oct", K: EncodeBase64URL(sym), KeyOps: []string{"encrypt"}},
			check: func(t *testing.T, material KeyMaterial, out model.JSONWebKey) {
				if !bytes.Equal(material.AES, sym) || out.K != "" {
					t.Fatalf("unexpected oct import: %+v %+v", material, out)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material, out, err := ImportKey(tt.jwk, "imported")
			if err != nil {
				t.Fatal(err)
			}
			if out.Kid != "imported" {
				t.Fatalf("unexpected kid %q", out.Kid)
			}
			tt.check(t, material, out)
		})
	}
}

func TestImportKeyErrors(t *testing.T) {
	tests := []model.JSONWebKey{
		{Kty: "unknown"},
		{Kty: "oct"},
		{Kty: "RSA"},
		{Kty: "EC", Crv: "P-256"},
		{Kty: "RSA", N: "!", E: EncodeBase64URL(big.NewInt(65537).Bytes())},
		{Kty: "EC", Crv: "P-999", X: EncodeBase64URL([]byte{1}), Y: EncodeBase64URL([]byte{2})},
	}
	for _, jwk := range tests {
		if _, _, err := ImportKey(jwk, "kid"); err == nil {
			t.Fatalf("expected error for %+v", jwk)
		}
	}
}

func TestJWKConverters(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	ecKey := mustECDSAKey(t, elliptic.P384())
	rsaJWK := RSAToJWK("kid", "RSA", []string{"sign"}, &rsaKey.PublicKey)
	if rsaJWK.N == "" || rsaJWK.E == "" || len(rsaJWK.KeyOps) != 1 {
		t.Fatalf("bad rsa jwk: %+v", rsaJWK)
	}
	ecJWK := ECDSAToJWK("kid", "EC", []string{"verify"}, "P-384", &ecKey.PublicKey)
	if ecJWK.X == "" || ecJWK.Y == "" || ecJWK.Crv != "P-384" {
		t.Fatalf("bad ec jwk: %+v", ecJWK)
	}
	symJWK := SymmetricToJWK("kid", "oct", []string{"wrapKey"}, []byte("0123456789abcdef"))
	if symJWK.K == "" || symJWK.Kty != "oct" {
		t.Fatalf("bad symmetric jwk: %+v", symJWK)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	rsaMaterial := KeyMaterial{RSA: rsaKey, RSAPub: &rsaKey.PublicKey}
	for _, alg := range []string{"RSA-OAEP", "RSA-OAEP-256", "RSA1_5"} {
		t.Run(alg, func(t *testing.T) {
			ciphertext, iv, err := Encrypt(rsaMaterial, "RSA", alg, []byte("hello rsa"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(iv) != 0 {
				t.Fatalf("unexpected iv %x", iv)
			}
			plaintext, outIV, err := Decrypt(rsaMaterial, "RSA", alg, ciphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(outIV) != 0 || string(plaintext) != "hello rsa" {
				t.Fatalf("unexpected decrypt result %q %x", plaintext, outIV)
			}
		})
	}

	aesTests := []struct {
		alg       string
		key       []byte
		plaintext []byte
	}{
		{alg: "A128CBC", key: []byte("0123456789abcdef"), plaintext: []byte("1234567890abcdef")},
		{alg: "A256CBC", key: []byte("0123456789abcdef0123456789abcdef"), plaintext: []byte("1234567890abcdef")},
		{alg: "A128CBCPAD", key: []byte("0123456789abcdef"), plaintext: []byte("pad me")},
		{alg: "A256CBCPAD", key: []byte("0123456789abcdef0123456789abcdef"), plaintext: []byte("pad me more")},
	}
	for _, tt := range aesTests {
		t.Run(tt.alg, func(t *testing.T) {
			material := KeyMaterial{AES: tt.key}
			ciphertext, iv, err := Encrypt(material, "oct", tt.alg, tt.plaintext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(iv) != 16 {
				t.Fatalf("unexpected iv len %d", len(iv))
			}
			plaintext, outIV, err := Decrypt(material, "oct", tt.alg, ciphertext, iv)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, tt.plaintext) || !bytes.Equal(outIV, iv) {
				t.Fatalf("unexpected plaintext %q", plaintext)
			}
		})
	}
}

func TestEncryptDecryptErrors(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	if _, _, err := Encrypt(KeyMaterial{}, "RSA", "RSA-OAEP", []byte("x"), nil); err == nil {
		t.Fatal("expected missing rsa public key error")
	}
	if _, _, err := Decrypt(KeyMaterial{}, "RSA", "RSA-OAEP", []byte("x"), nil); err == nil {
		t.Fatal("expected missing rsa private key error")
	}
	if _, _, err := Encrypt(KeyMaterial{RSA: rsaKey, RSAPub: &rsaKey.PublicKey}, "RSA", "bogus", []byte("x"), nil); err == nil {
		t.Fatal("expected unsupported rsa encrypt algorithm")
	}
	if _, _, err := Decrypt(KeyMaterial{RSA: rsaKey}, "RSA", "bogus", []byte("x"), nil); err == nil {
		t.Fatal("expected unsupported rsa decrypt algorithm")
	}
	if _, _, err := Encrypt(KeyMaterial{AES: []byte("short")}, "oct", "A128CBC", []byte("1234567890abcdef"), make([]byte, 16)); err == nil {
		t.Fatal("expected aes key size error")
	}
	if _, _, err := Encrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBC", []byte("short"), make([]byte, 16)); err == nil {
		t.Fatal("expected block size error")
	}
	if _, _, err := Encrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBCPAD", []byte("x"), []byte("iv")); err == nil {
		t.Fatal("expected iv error")
	}
	if _, _, err := Decrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBC", []byte("123"), make([]byte, 16)); err == nil {
		t.Fatal("expected ciphertext size error")
	}
	badPadded, iv, err := Encrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBCPAD", []byte("bad padding"), make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	badPadded[len(badPadded)-1] ^= 0xff
	if _, _, err := Decrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBCPAD", badPadded, iv); err == nil {
		t.Fatal("expected padding error")
	}
	if _, _, err := Encrypt(KeyMaterial{}, "EC", "ES256", []byte("x"), nil); err == nil {
		t.Fatal("expected unsupported encrypt kty")
	}
	if _, _, err := Decrypt(KeyMaterial{}, "EC", "ES256", []byte("x"), nil); err == nil {
		t.Fatal("expected unsupported decrypt kty")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	rsaMaterial := KeyMaterial{RSA: rsaKey, RSAPub: &rsaKey.PublicKey}
	message := []byte("sign me")
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			digest := DigestForAlg(alg, message)
			sig, err := Sign(rsaMaterial, "RSA", alg, digest)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := Verify(rsaMaterial, "RSA", alg, digest, sig)
			if err != nil || !ok {
				t.Fatalf("verify failed ok=%v err=%v", ok, err)
			}
			ok, err = Verify(rsaMaterial, "RSA", alg, digest, append([]byte(nil), sig[:len(sig)-1]...))
			if err != nil || ok {
				t.Fatalf("expected invalid signature ok=%v err=%v", ok, err)
			}
		})
	}

	ecTests := []struct {
		alg   string
		curve elliptic.Curve
		crv   string
	}{
		{alg: "ES256", curve: elliptic.P256(), crv: "P-256"},
		{alg: "ES384", curve: elliptic.P384(), crv: "P-384"},
		{alg: "ES512", curve: elliptic.P521(), crv: "P-521"},
	}
	for _, tt := range ecTests {
		t.Run(tt.alg, func(t *testing.T) {
			key := mustECDSAKey(t, tt.curve)
			material := KeyMaterial{ECDSA: key, ECDSAPub: &key.PublicKey}
			digest := DigestForAlg(tt.alg, message)
			sig, err := Sign(material, "EC", tt.alg, digest)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := Verify(material, "EC", tt.alg, digest, sig)
			if err != nil || !ok {
				t.Fatalf("verify failed ok=%v err=%v", ok, err)
			}
			ok, err = Verify(material, "EC", tt.alg, digest, sig[:len(sig)-1])
			if err != nil || ok {
				t.Fatalf("expected invalid signature length ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestSignVerifyErrors(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	if _, err := Sign(KeyMaterial{}, "RSA", "RS256", []byte("digest")); err == nil {
		t.Fatal("expected missing rsa private key error")
	}
	if _, err := Sign(KeyMaterial{RSA: rsaKey}, "RSA", "bogus", []byte("digest")); err == nil {
		t.Fatal("expected unsupported signing algorithm")
	}
	if _, err := Sign(KeyMaterial{}, "EC", "ES256", []byte("digest")); err == nil {
		t.Fatal("expected missing ecdsa private key error")
	}
	if _, err := Sign(KeyMaterial{}, "oct", "HS256", []byte("digest")); err == nil {
		t.Fatal("expected unsupported sign kty")
	}
	if _, err := Verify(KeyMaterial{}, "RSA", "RS256", []byte("digest"), []byte("sig")); err == nil {
		t.Fatal("expected missing rsa public key error")
	}
	if _, err := Verify(KeyMaterial{RSAPub: &rsaKey.PublicKey}, "RSA", "bogus", []byte("digest"), []byte("sig")); err == nil {
		t.Fatal("expected unsupported verify algorithm")
	}
	if _, err := Verify(KeyMaterial{}, "EC", "ES256", []byte("digest"), []byte("sig")); err == nil {
		t.Fatal("expected missing ecdsa public key error")
	}
	if _, err := Verify(KeyMaterial{}, "oct", "HS256", []byte("digest"), []byte("sig")); err == nil {
		t.Fatal("expected unsupported verify kty")
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	wrapped, err := Wrap(KeyMaterial{RSA: rsaKey, RSAPub: &rsaKey.PublicKey}, "RSA", "RSA-OAEP", []byte("12345678"))
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := Unwrap(KeyMaterial{RSA: rsaKey, RSAPub: &rsaKey.PublicKey}, "RSA", "RSA-OAEP", wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(unwrapped) != "12345678" {
		t.Fatalf("unexpected rsa unwrap %q", unwrapped)
	}
	for _, key := range [][]byte{[]byte("0123456789abcdef"), []byte("0123456789abcdefghijklmn"), []byte("0123456789abcdef0123456789abcdef")} {
		wrapped, err := Wrap(KeyMaterial{AES: key}, "oct", mapKWAlg(len(key)), []byte("12345678ABCDEFGH"))
		if err != nil {
			t.Fatal(err)
		}
		unwrapped, err := Unwrap(KeyMaterial{AES: key}, "oct", mapKWAlg(len(key)), wrapped)
		if err != nil {
			t.Fatal(err)
		}
		if string(unwrapped) != "12345678ABCDEFGH" {
			t.Fatalf("unexpected aes unwrap %q", unwrapped)
		}
	}
}

func TestWrapUnwrapErrors(t *testing.T) {
	rsaKey := mustRSAKey(t, 1024)
	if _, err := Wrap(KeyMaterial{}, "RSA", "RSA-OAEP", []byte("12345678")); err == nil {
		t.Fatal("expected missing rsa public key")
	}
	if _, err := Unwrap(KeyMaterial{}, "RSA", "RSA-OAEP", []byte("cipher")); err == nil {
		t.Fatal("expected missing rsa private key")
	}
	if _, err := Wrap(KeyMaterial{RSA: rsaKey, RSAPub: &rsaKey.PublicKey}, "octagon", "A128KW", []byte("12345678")); err == nil {
		t.Fatal("expected unsupported wrap kty")
	}
	if _, err := Unwrap(KeyMaterial{RSA: rsaKey}, "octagon", "A128KW", []byte("cipher")); err == nil {
		t.Fatal("expected unsupported unwrap kty")
	}
	if _, err := Wrap(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128KW", []byte("short")); err == nil {
		t.Fatal("expected aes key wrap size error")
	}
	wrapped, err := Wrap(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128KW", []byte("12345678ABCDEFGH"))
	if err != nil {
		t.Fatal(err)
	}
	wrapped[0] ^= 0xff
	if _, err := Unwrap(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128KW", wrapped); err == nil {
		t.Fatal("expected aes integrity error")
	}
}

func TestHelpers(t *testing.T) {
	if hash := HashForAlg("RS256"); hash != crypto.SHA256 {
		t.Fatalf("unexpected hash %v", hash)
	}
	if hash := HashForAlg("ES384"); hash != crypto.SHA384 {
		t.Fatalf("unexpected hash %v", hash)
	}
	if hash := HashForAlg("PS512"); hash != crypto.SHA512 {
		t.Fatalf("unexpected hash %v", hash)
	}
	if hash := HashForAlg("none"); hash != 0 {
		t.Fatalf("unexpected hash %v", hash)
	}
	if got := DigestForAlg("none", []byte("raw")); string(got) != "raw" {
		t.Fatalf("unexpected digest %q", got)
	}
	if got := len(DigestForAlg("RS256", []byte("raw"))); got != 32 {
		t.Fatalf("unexpected sha256 digest len %d", got)
	}
	if got := len(DigestForAlg("RS384", []byte("raw"))); got != 48 {
		t.Fatalf("unexpected sha384 digest len %d", got)
	}
	if got := len(DigestForAlg("RS512", []byte("raw"))); got != 64 {
		t.Fatalf("unexpected sha512 digest len %d", got)
	}
	if _, crv, err := resolveCurve(""); err != nil || crv != "P-256" {
		t.Fatalf("unexpected resolveCurve result %q %v", crv, err)
	}
	if _, _, err := resolveCurve("P-999"); err == nil {
		t.Fatal("expected resolveCurve error")
	}
	if _, _, err := rsaHash("bogus"); err == nil {
		t.Fatal("expected rsaHash error")
	}
	if got := mapKWAlg(24); got != "A192KW" {
		t.Fatalf("unexpected kw alg %q", got)
	}
	if got := mapKWAlg(99); got != "A256KW" {
		t.Fatalf("unexpected kw alg %q", got)
	}
	if got := xor64([]byte{0, 0, 0, 0, 0, 0, 0, 1}, 1); !bytes.Equal(got, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("unexpected xor result %v", got)
	}
	bi, err := decodeBigInt(EncodeBase64URL([]byte{1, 2, 3}))
	if err != nil || bi.Cmp(big.NewInt(0).SetBytes([]byte{1, 2, 3})) != 0 {
		t.Fatalf("unexpected bigint %v %v", bi, err)
	}
	if _, err := decodeBigInt("!"); err == nil {
		t.Fatal("expected decodeBigInt error")
	}
	if got := padBytes([]byte{1, 2}, 4); !bytes.Equal(got, []byte{0, 0, 1, 2}) {
		t.Fatalf("unexpected padBytes result %v", got)
	}
	if got := pkcs7Pad([]byte("abc"), 8); len(got)%8 != 0 {
		t.Fatalf("unexpected padded len %d", len(got))
	}
	if _, err := pkcs7Unpad([]byte{}, 8); err == nil {
		t.Fatal("expected pkcs7 empty error")
	}
	if _, err := pkcs7Unpad([]byte{1, 2, 3, 0}, 4); err == nil {
		t.Fatal("expected pkcs7 invalid padding error")
	}
	if _, err := selectAESKey([]byte("0123456789abcdef"), "bogus"); err == nil {
		t.Fatal("expected selectAESKey error")
	}
	if _, err := selectAESKey([]byte("short"), "A128KW"); err == nil {
		t.Fatal("expected selectAESKey size error")
	}
	if _, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte("ok"))); err != nil {
		t.Fatal(err)
	}
}

func TestAdditionalCryptoCoverage(t *testing.T) {
	if _, err := Wrap(KeyMaterial{}, "EC", "ES256", []byte("x")); err == nil {
		t.Fatal("expected unsupported wrap for ec")
	}
	if _, err := Unwrap(KeyMaterial{}, "EC", "ES256", []byte("x")); err == nil {
		t.Fatal("expected unsupported unwrap for ec")
	}
	oldRead := randRead
	randRead = func(_ []byte) (int, error) { return 0, errors.New("boom") }
	if _, _, err := Encrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBC", []byte("1234567890abcdef"), nil); err == nil {
		t.Fatal("expected iv generation error")
	}
	randRead = oldRead
	if _, _, err := Decrypt(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128CBC", []byte("1234567890abcdef"), []byte("short")); err == nil {
		t.Fatal("expected invalid iv size")
	}
	if _, err := Unwrap(KeyMaterial{AES: []byte("0123456789abcdef")}, "oct", "A128KW", []byte("short")); err == nil {
		t.Fatal("expected short unwrap error")
	}
	key := mustRSAKey(t, 1024)
	bad := rsaPrivateJWK(key)
	bad.D = "!"
	if _, _, err := ImportKey(bad, "kid"); err == nil {
		t.Fatal("expected invalid rsa private exponent")
	}
}

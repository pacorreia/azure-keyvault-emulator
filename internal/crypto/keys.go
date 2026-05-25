package crypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/pacorreia/azure-keyvault-emulator/internal/model"
)

type KeyMaterial struct {
	RSA      *rsa.PrivateKey
	ECDSA    *ecdsa.PrivateKey
	AES      []byte
	RSAPub   *rsa.PublicKey
	ECDSAPub *ecdsa.PublicKey
}

func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func DecodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func GenerateKey(kty string, keySize int, crv, kid string, keyOps []string) (KeyMaterial, model.JSONWebKey, error) {
	switch kty {
	case "RSA", "RSA-HSM":
		if keySize == 0 {
			keySize = 2048
		}
		priv, err := rsa.GenerateKey(crand.Reader, keySize)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		return KeyMaterial{RSA: priv, RSAPub: &priv.PublicKey}, RSAToJWK(kid, kty, keyOps, &priv.PublicKey), nil
	case "EC", "EC-HSM":
		curve, resolvedCrv, err := resolveCurve(crv)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		priv, err := ecdsa.GenerateKey(curve, crand.Reader)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		return KeyMaterial{ECDSA: priv, ECDSAPub: &priv.PublicKey}, ECDSAToJWK(kid, kty, keyOps, resolvedCrv, &priv.PublicKey), nil
	case "oct", "oct-HSM":
		if keySize == 0 {
			keySize = 256
		}
		if keySize%8 != 0 {
			return KeyMaterial{}, model.JSONWebKey{}, fmt.Errorf("invalid symmetric key size")
		}
		buf := make([]byte, keySize/8)
		if _, err := crand.Read(buf); err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		return KeyMaterial{AES: buf}, SymmetricToJWK(kid, kty, keyOps, nil), nil
	default:
		return KeyMaterial{}, model.JSONWebKey{}, fmt.Errorf("unsupported key type %q", kty)
	}
}

func ImportKey(jwk model.JSONWebKey, kid string) (KeyMaterial, model.JSONWebKey, error) {
	switch jwk.Kty {
	case "oct", "oct-HSM":
		if jwk.K == "" {
			return KeyMaterial{}, model.JSONWebKey{}, errors.New("missing key material")
		}
		key, err := DecodeBase64URL(jwk.K)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		return KeyMaterial{AES: key}, SymmetricToJWK(kid, jwk.Kty, jwk.KeyOps, nil), nil
	case "RSA", "RSA-HSM":
		if jwk.N == "" || jwk.E == "" {
			return KeyMaterial{}, model.JSONWebKey{}, errors.New("missing rsa modulus or exponent")
		}
		n, err := decodeBigInt(jwk.N)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		eBig, err := decodeBigInt(jwk.E)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		pub := &rsa.PublicKey{N: n, E: int(eBig.Int64())}
		material := KeyMaterial{RSAPub: pub}
		if jwk.D != "" {
			d, err := decodeBigInt(jwk.D)
			if err != nil {
				return KeyMaterial{}, model.JSONWebKey{}, err
			}
			priv := &rsa.PrivateKey{PublicKey: *pub, D: d}
			if jwk.P != "" && jwk.Q != "" {
				p, err := decodeBigInt(jwk.P)
				if err != nil {
					return KeyMaterial{}, model.JSONWebKey{}, err
				}
				q, err := decodeBigInt(jwk.Q)
				if err != nil {
					return KeyMaterial{}, model.JSONWebKey{}, err
				}
				priv.Primes = []*big.Int{p, q}
				priv.Precompute()
			}
			material.RSA = priv
		}
		return material, RSAToJWK(kid, jwk.Kty, jwk.KeyOps, pub), nil
	case "EC", "EC-HSM":
		curve, resolvedCrv, err := resolveCurve(jwk.Crv)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		if jwk.X == "" || jwk.Y == "" {
			return KeyMaterial{}, model.JSONWebKey{}, errors.New("missing ec coordinates")
		}
		x, err := decodeBigInt(jwk.X)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		y, err := decodeBigInt(jwk.Y)
		if err != nil {
			return KeyMaterial{}, model.JSONWebKey{}, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		material := KeyMaterial{ECDSAPub: pub}
		if jwk.D != "" {
			d, err := decodeBigInt(jwk.D)
			if err != nil {
				return KeyMaterial{}, model.JSONWebKey{}, err
			}
			material.ECDSA = &ecdsa.PrivateKey{PublicKey: *pub, D: d}
		}
		return material, ECDSAToJWK(kid, jwk.Kty, jwk.KeyOps, resolvedCrv, pub), nil
	default:
		return KeyMaterial{}, model.JSONWebKey{}, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
}

func RSAToJWK(kid, kty string, ops []string, pub *rsa.PublicKey) model.JSONWebKey {
	return model.JSONWebKey{
		Kid:    kid,
		Kty:    kty,
		KeyOps: append([]string(nil), ops...),
		N:      EncodeBase64URL(pub.N.Bytes()),
		E:      EncodeBase64URL(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ECDSAToJWK(kid, kty string, ops []string, crv string, pub *ecdsa.PublicKey) model.JSONWebKey {
	size := (pub.Params().BitSize + 7) / 8
	return model.JSONWebKey{
		Kid:    kid,
		Kty:    kty,
		KeyOps: append([]string(nil), ops...),
		Crv:    crv,
		X:      EncodeBase64URL(padBytes(pub.X.Bytes(), size)),
		Y:      EncodeBase64URL(padBytes(pub.Y.Bytes(), size)),
	}
}

func SymmetricToJWK(kid, kty string, ops []string, key []byte) model.JSONWebKey {
	jwk := model.JSONWebKey{Kid: kid, Kty: kty, KeyOps: append([]string(nil), ops...)}
	if key != nil {
		jwk.K = EncodeBase64URL(key)
	}
	return jwk
}

func Encrypt(material KeyMaterial, kty, alg string, plaintext []byte, iv []byte) ([]byte, []byte, error) {
	switch {
	case strings.HasPrefix(kty, "RSA"):
		pub := material.RSAPub
		if material.RSA != nil {
			pub = &material.RSA.PublicKey
		}
		if pub == nil {
			return nil, nil, errors.New("rsa public key not available")
		}
		switch alg {
		case "RSA-OAEP":
			out, err := rsa.EncryptOAEP(sha1.New(), crand.Reader, pub, plaintext, nil)
			return out, nil, err
		case "RSA-OAEP-256":
			out, err := rsa.EncryptOAEP(sha256.New(), crand.Reader, pub, plaintext, nil)
			return out, nil, err
		case "RSA1_5":
			out, err := rsa.EncryptPKCS1v15(crand.Reader, pub, plaintext)
			return out, nil, err
		default:
			return nil, nil, fmt.Errorf("unsupported encrypt algorithm %q", alg)
		}
	case strings.HasPrefix(kty, "oct"):
		return encryptCBC(material.AES, alg, plaintext, iv)
	default:
		return nil, nil, fmt.Errorf("encrypt not supported for %q", kty)
	}
}

func Decrypt(material KeyMaterial, kty, alg string, ciphertext []byte, iv []byte) ([]byte, []byte, error) {
	switch {
	case strings.HasPrefix(kty, "RSA"):
		if material.RSA == nil {
			return nil, nil, errors.New("rsa private key not available")
		}
		switch alg {
		case "RSA-OAEP":
			out, err := rsa.DecryptOAEP(sha1.New(), crand.Reader, material.RSA, ciphertext, nil)
			return out, nil, err
		case "RSA-OAEP-256":
			out, err := rsa.DecryptOAEP(sha256.New(), crand.Reader, material.RSA, ciphertext, nil)
			return out, nil, err
		case "RSA1_5":
			out, err := rsa.DecryptPKCS1v15(crand.Reader, material.RSA, ciphertext)
			return out, nil, err
		default:
			return nil, nil, fmt.Errorf("unsupported decrypt algorithm %q", alg)
		}
	case strings.HasPrefix(kty, "oct"):
		return decryptCBC(material.AES, alg, ciphertext, iv)
	default:
		return nil, nil, fmt.Errorf("decrypt not supported for %q", kty)
	}
}

func Sign(material KeyMaterial, kty, alg string, digest []byte) ([]byte, error) {
	switch {
	case strings.HasPrefix(kty, "RSA"):
		if material.RSA == nil {
			return nil, errors.New("rsa private key not available")
		}
		hash, pss, err := rsaHash(alg)
		if err != nil {
			return nil, err
		}
		if pss {
			return rsa.SignPSS(crand.Reader, material.RSA, hash, digest, nil)
		}
		return rsa.SignPKCS1v15(crand.Reader, material.RSA, hash, digest)
	case strings.HasPrefix(kty, "EC"):
		if material.ECDSA == nil {
			return nil, errors.New("ecdsa private key not available")
		}
		size := (material.ECDSA.Params().BitSize + 7) / 8
		r, s, err := ecdsa.Sign(crand.Reader, material.ECDSA, digest)
		if err != nil {
			return nil, err
		}
		rb := padBytes(r.Bytes(), size)
		sb := padBytes(s.Bytes(), size)
		return append(rb, sb...), nil
	default:
		return nil, fmt.Errorf("sign not supported for %q", kty)
	}
}

func Verify(material KeyMaterial, kty, alg string, digest, signature []byte) (bool, error) {
	switch {
	case strings.HasPrefix(kty, "RSA"):
		pub := material.RSAPub
		if material.RSA != nil {
			pub = &material.RSA.PublicKey
		}
		if pub == nil {
			return false, errors.New("rsa public key not available")
		}
		hash, pss, err := rsaHash(alg)
		if err != nil {
			return false, err
		}
		if pss {
			if err := rsa.VerifyPSS(pub, hash, digest, signature, nil); err != nil {
				return false, nil
			}
			return true, nil
		}
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, signature); err != nil {
			return false, nil
		}
		return true, nil
	case strings.HasPrefix(kty, "EC"):
		pub := material.ECDSAPub
		if material.ECDSA != nil {
			pub = &material.ECDSA.PublicKey
		}
		if pub == nil {
			return false, errors.New("ecdsa public key not available")
		}
		size := (pub.Params().BitSize + 7) / 8
		if len(signature) != size*2 {
			return false, nil
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		return ecdsa.Verify(pub, digest, r, s), nil
	default:
		return false, fmt.Errorf("verify not supported for %q", kty)
	}
}

func Wrap(material KeyMaterial, kty, alg string, plaintext []byte) ([]byte, error) {
	switch {
	case strings.HasPrefix(kty, "RSA"):
		out, _, err := Encrypt(material, kty, alg, plaintext, nil)
		return out, err
	case strings.HasPrefix(kty, "oct"):
		return aesKeyWrap(material.AES, plaintext)
	default:
		return nil, fmt.Errorf("wrap not supported for %q", kty)
	}
}

func Unwrap(material KeyMaterial, kty, alg string, ciphertext []byte) ([]byte, error) {
	switch {
	case strings.HasPrefix(kty, "RSA"):
		out, _, err := Decrypt(material, kty, alg, ciphertext, nil)
		return out, err
	case strings.HasPrefix(kty, "oct"):
		return aesKeyUnwrap(material.AES, ciphertext)
	default:
		return nil, fmt.Errorf("unwrap not supported for %q", kty)
	}
}

func resolveCurve(crv string) (elliptic.Curve, string, error) {
	switch crv {
	case "", "P-256":
		return elliptic.P256(), "P-256", nil
	case "P-384":
		return elliptic.P384(), "P-384", nil
	case "P-521":
		return elliptic.P521(), "P-521", nil
	default:
		return nil, "", fmt.Errorf("unsupported curve %q", crv)
	}
}

func rsaHash(alg string) (crypto.Hash, bool, error) {
	switch alg {
	case "RS256":
		return crypto.SHA256, false, nil
	case "RS384":
		return crypto.SHA384, false, nil
	case "RS512":
		return crypto.SHA512, false, nil
	case "PS256":
		return crypto.SHA256, true, nil
	case "PS384":
		return crypto.SHA384, true, nil
	case "PS512":
		return crypto.SHA512, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
}

func encryptCBC(key []byte, alg string, plaintext, iv []byte) ([]byte, []byte, error) {
	if len(iv) == 0 {
		iv = make([]byte, aes.BlockSize)
		if _, err := crand.Read(iv); err != nil {
			return nil, nil, err
		}
	}
	if len(iv) != aes.BlockSize {
		return nil, nil, errors.New("iv must be 16 bytes")
	}
	key, err := selectAESKey(key, alg)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	input := append([]byte(nil), plaintext...)
	if strings.HasSuffix(alg, "PAD") {
		input = pkcs7Pad(input, aes.BlockSize)
	} else if len(input)%aes.BlockSize != 0 {
		return nil, nil, errors.New("plaintext size must be a multiple of 16 bytes")
	}
	out := make([]byte, len(input))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, input)
	return out, iv, nil
}

func decryptCBC(key []byte, alg string, ciphertext, iv []byte) ([]byte, []byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, nil, errors.New("iv must be 16 bytes")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, nil, errors.New("ciphertext size must be a multiple of 16 bytes")
	}
	key, err := selectAESKey(key, alg)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	if strings.HasSuffix(alg, "PAD") {
		out, err = pkcs7Unpad(out, aes.BlockSize)
		if err != nil {
			return nil, nil, err
		}
	}
	return out, iv, nil
}

func selectAESKey(key []byte, alg string) ([]byte, error) {
	var size int
	switch alg {
	case "A128CBC", "A128CBCPAD", "A128KW":
		size = 16
	case "A192KW":
		size = 24
	case "A256CBC", "A256CBCPAD", "A256KW":
		size = 32
	default:
		return nil, fmt.Errorf("unsupported symmetric algorithm %q", alg)
	}
	if len(key) != size {
		return nil, fmt.Errorf("algorithm %s requires a %d-byte key", alg, size)
	}
	return key, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if _, err := selectAESKey(kek, mapKWAlg(len(kek))); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext)%8 != 0 {
		return nil, errors.New("plaintext must be a non-empty multiple of 8 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	a := []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = append([]byte(nil), plaintext[i*8:(i+1)*8]...)
	}
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i + 1)
			a = xor64(buf[:8], t)
			r[i] = append([]byte(nil), buf[8:]...)
		}
	}
	out := append([]byte(nil), a...)
	for i := 0; i < n; i++ {
		out = append(out, r[i]...)
	}
	return out, nil
}

func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if _, err := selectAESKey(kek, mapKWAlg(len(kek))); err != nil {
		return nil, err
	}
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, errors.New("ciphertext must be at least 16 bytes and a multiple of 8")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)/8 - 1
	a := append([]byte(nil), ciphertext[:8]...)
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = append([]byte(nil), ciphertext[(i+1)*8:(i+2)*8]...)
	}
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			copy(buf[:8], xor64(a, t))
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			a = append([]byte(nil), buf[:8]...)
			r[i] = append([]byte(nil), buf[8:]...)
		}
	}
	if !bytes.Equal(a, []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}) {
		return nil, errors.New("integrity check failed")
	}
	out := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		out = append(out, r[i]...)
	}
	return out, nil
}

func mapKWAlg(keyLen int) string {
	switch keyLen {
	case 16:
		return "A128KW"
	case 24:
		return "A192KW"
	default:
		return "A256KW"
	}
}

func xor64(in []byte, t uint64) []byte {
	out := append([]byte(nil), in...)
	for i := 0; i < 8; i++ {
		out[7-i] ^= byte(t & 0xff)
		t >>= 8
	}
	return out
}

func decodeBigInt(value string) (*big.Int, error) {
	data, err := DecodeBase64URL(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

func padBytes(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	out := make([]byte, size)
	copy(out[size-len(data):], data)
	return out
}

func HashForAlg(alg string) crypto.Hash {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256
	case "RS384", "PS384", "ES384":
		return crypto.SHA384
	case "RS512", "PS512", "ES512":
		return crypto.SHA512
	default:
		return 0
	}
}

func DigestForAlg(alg string, data []byte) []byte {
	switch HashForAlg(alg) {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	default:
		return append([]byte(nil), data...)
	}
}

package model

type JSONWebKey struct {
	Kid    string   `json:"kid,omitempty"`
	Kty    string   `json:"kty,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	D      string   `json:"d,omitempty"`
	P      string   `json:"p,omitempty"`
	Q      string   `json:"q,omitempty"`
	DP     string   `json:"dp,omitempty"`
	DQ     string   `json:"dq,omitempty"`
	QI     string   `json:"qi,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	K      string   `json:"k,omitempty"`
}

type CreateKeyRequest struct {
	Kty        string            `json:"kty"`
	KeySize    int               `json:"key_size,omitempty"`
	KeyOps     []string          `json:"key_ops,omitempty"`
	Attributes *Attributes       `json:"attributes,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Crv        string            `json:"crv,omitempty"`
	Value      string            `json:"value,omitempty"`
}

type ImportKeyRequest struct {
	Key        JSONWebKey        `json:"key"`
	Attributes *Attributes       `json:"attributes,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type UpdateKeyRequest struct {
	Attributes *Attributes       `json:"attributes,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	KeyOps     []string          `json:"key_ops,omitempty"`
}

type KeyBundle struct {
	Key        JSONWebKey        `json:"key"`
	Attributes Attributes        `json:"attributes"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type KeyItem struct {
	Kid        string            `json:"kid,omitempty"`
	Attributes Attributes        `json:"attributes"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type DeletedKeyBundle struct {
	KeyBundle
	RecoveryID         string `json:"recoveryId,omitempty"`
	DeletedDate        int64  `json:"deletedDate,omitempty"`
	ScheduledPurgeDate int64  `json:"scheduledPurgeDate,omitempty"`
}

type EncryptRequest struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
	IV    string `json:"iv,omitempty"`
}

type CryptoResponse struct {
	Kid   string `json:"kid,omitempty"`
	Value string `json:"value,omitempty"`
	Alg   string `json:"alg,omitempty"`
	IV    string `json:"iv,omitempty"`
}

type SignRequest struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

type VerifyRequest struct {
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
	Value  string `json:"value"`
}

type VerifyResponse struct {
	Value bool `json:"value"`
}

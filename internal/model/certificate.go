package model

type CertificatePolicy struct {
	ID              string           `json:"id,omitempty"`
	Issuer          map[string]any   `json:"issuer,omitempty"`
	KeyProps        map[string]any   `json:"key_props,omitempty"`
	SecretProps     map[string]any   `json:"secret_props,omitempty"`
	X509Props       map[string]any   `json:"x509_props,omitempty"`
	LifetimeActions []map[string]any `json:"lifetime_actions,omitempty"`
	Attributes      map[string]any   `json:"attributes,omitempty"`
}

type CreateCertificateRequest struct {
	Policy     *CertificatePolicy `json:"policy,omitempty"`
	Attributes *Attributes        `json:"attributes,omitempty"`
	Tags       map[string]string  `json:"tags,omitempty"`
}

type ImportCertificateRequest struct {
	Value      string             `json:"value"`
	Password   string             `json:"pwd,omitempty"`
	Policy     *CertificatePolicy `json:"policy,omitempty"`
	Attributes *Attributes        `json:"attributes,omitempty"`
	Tags       map[string]string  `json:"tags,omitempty"`
}

type UpdateCertificateRequest struct {
	Attributes *Attributes       `json:"attributes,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type CertificateBundle struct {
	ID         string             `json:"id,omitempty"`
	Kid        string             `json:"kid,omitempty"`
	Sid        string             `json:"sid,omitempty"`
	Cer        string             `json:"cer,omitempty"`
	Attributes Attributes         `json:"attributes"`
	Tags       map[string]string  `json:"tags,omitempty"`
	Policy     *CertificatePolicy `json:"policy,omitempty"`
}

type CertificateItem struct {
	ID         string            `json:"id,omitempty"`
	Kid        string            `json:"kid,omitempty"`
	Sid        string            `json:"sid,omitempty"`
	X5t        string            `json:"x5t,omitempty"`
	Attributes Attributes        `json:"attributes"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type DeletedCertificateBundle struct {
	CertificateBundle
	RecoveryID         string `json:"recoveryId,omitempty"`
	DeletedDate        int64  `json:"deletedDate,omitempty"`
	ScheduledPurgeDate int64  `json:"scheduledPurgeDate,omitempty"`
}

type CertificateOperation struct {
	ID            string `json:"id,omitempty"`
	Status        string `json:"status"`
	Target        string `json:"target,omitempty"`
	StatusDetails string `json:"status_details,omitempty"`
}

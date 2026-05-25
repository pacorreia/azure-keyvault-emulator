package model

type SecretSetRequest struct {
	Value       string            `json:"value"`
	ContentType string            `json:"contentType,omitempty"`
	Attributes  *Attributes       `json:"attributes,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type SecretUpdateRequest struct {
	ContentType *string           `json:"contentType,omitempty"`
	Attributes  *Attributes       `json:"attributes,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type SecretBundle struct {
	Value       string            `json:"value,omitempty"`
	ID          string            `json:"id,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	Attributes  Attributes        `json:"attributes"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type SecretItem struct {
	ID          string            `json:"id,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	Attributes  Attributes        `json:"attributes"`
	Tags        map[string]string `json:"tags,omitempty"`
}

type DeletedSecretBundle struct {
	SecretBundle
	RecoveryID         string `json:"recoveryId,omitempty"`
	DeletedDate        int64  `json:"deletedDate,omitempty"`
	ScheduledPurgeDate int64  `json:"scheduledPurgeDate,omitempty"`
}

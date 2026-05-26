package model

type Attributes struct {
	Enabled         *bool  `json:"enabled,omitempty"`
	NotBefore       *int64 `json:"nbf,omitempty"`
	Expires         *int64 `json:"exp,omitempty"`
	Created         int64  `json:"created,omitempty"`
	Updated         int64  `json:"updated,omitempty"`
	RecoveryLevel   string `json:"recoveryLevel,omitempty"`
	RecoverableDays int    `json:"recoverableDays,omitempty"`
}

type ListResult[T any] struct {
	Value    []T     `json:"value"`
	NextLink *string `json:"nextLink,omitempty"`
}

package model

type CloudError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type KeyVaultError struct {
	Error CloudError `json:"error"`
}

func NewKeyVaultError(code, message string) KeyVaultError {
	return KeyVaultError{Error: CloudError{Code: code, Message: message}}
}

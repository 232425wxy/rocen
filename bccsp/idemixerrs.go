package bccsp

import "fmt"

type IdemixIssuerPublicKeyImportErrorType int

const (
	IdemixIssuerPublicKeyImportUnmarshallingError IdemixIssuerPublicKeyImportErrorType = iota
	IdemixIssuerPublicKeyImportHashError
	IdemixIssuerPublicKeyImportValidationError
	IdemixIssuerPublicKeyImportNumAttributesError
	IdemixIssuerPublicKeyImportAttributeNameError
)

type IdemixIssuerPublicKeyImportError struct {
	Type IdemixIssuerPublicKeyImportErrorType
	ErrorMsg string
	Cause error
}

func (err *IdemixIssuerPublicKeyImportError) Error() string {
	if err.Cause != nil {
		return fmt.Sprintf("%s: %s", err.ErrorMsg, err.Cause)
	}
	return err.ErrorMsg
}
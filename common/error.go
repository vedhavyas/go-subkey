package common

// Error is alias for string with errors.Error implementation.
type Error string

// Error returns the error in string.
func (se Error) Error() string {
	return string(se)
}

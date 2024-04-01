package subcommand

import "fmt"

var ErrNotImplemented *OracleError = NewOracleError("not implemeneted", nil)

type OracleError struct {
	msg   string
	child error
}

func (or *OracleError) Error() string {
	if or.child == nil {
		return or.msg
	} else {
		return fmt.Sprintf("%s: %s", or.msg, or.child)
	}
}

func NewOracleError(msg string, child error) *OracleError {
	or := OracleError{msg, child}
	return &or
}

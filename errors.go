package netforensics

import "errors"

var ErrInvalidAddress = errors.New("invalid IP address")
var ErrApplicationMessageBudget = errors.New("application message budget exhausted")

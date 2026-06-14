package sshreq

// I don't know why pflag doesn't export something like NewStringValue
// Copy it here
type stringValue string

func NewStringValue(val string, p *string) *stringValue {
	*p = val
	return (*stringValue)(p)
}

func (s *stringValue) Set(val string) error {
	*s = stringValue(val)
	return nil
}

func (s *stringValue) Type() string {
	return "string"
}

func (s *stringValue) String() string { return string(*s) }

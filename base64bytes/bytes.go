package base64bytes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

type Bytes []byte

var _ json.Marshaler = Bytes(nil)

func NewBytes(s string) Bytes {
	bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return bytes
}

func (b Bytes) MarshalJSON() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	_, err := enc.Write(b)
	if err != nil {
		return nil, err
	}
	enc.Close()

	return json.Marshal(buf.String())
}

func (b Bytes) String() string {
	return base64.StdEncoding.EncodeToString(b)
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var buf string
	err := json.Unmarshal(data, &buf)
	if err != nil {
		return err
	}
	*b, err = base64.StdEncoding.DecodeString(buf)
	return err
}

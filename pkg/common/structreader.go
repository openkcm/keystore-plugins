package common

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"
)

var (
	ErrFieldMissing = errors.New("field is missing")
	ErrFieldEmpty   = errors.New("field is empty")
	ErrNilConfig    = errors.New("config is nil")
)

// StructReader provides methods to safely extract values from structpb.Struct
type StructReader struct {
	fields map[string]*structpb.Value
}

// NewStructReader creates a new StructReader from a structpb.Struct
func NewStructReader(config *structpb.Struct) (*StructReader, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	return &StructReader{fields: config.Fields}, nil
}

// GetString safely extracts string values from configuration
func (r *StructReader) GetString(key string) (string, error) {
	value, ok := r.fields[key]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrFieldMissing, key)
	}

	strValue := value.GetStringValue()
	if strValue == "" {
		return "", fmt.Errorf("%w: %s", ErrFieldEmpty, key)
	}

	return strValue, nil
}

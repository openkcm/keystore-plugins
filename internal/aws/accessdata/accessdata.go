package accessdata

import (
	"google.golang.org/protobuf/types/known/structpb"
)

// Field name constants shared between keystoremang and keystoreop.
const (
	FieldTrustAnchorArn = "trustAnchorArn"
	FieldRoleArn        = "roleArn"
	FieldProfileArn     = "profileArn"
)

// ToStruct encodes AWS RolesAnywhere ARNs into a structpb.Struct using canonical field names.
func ToStruct(trustAnchorArn, roleArn, profileArn string) *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			FieldTrustAnchorArn: structpb.NewStringValue(trustAnchorArn),
			FieldRoleArn:        structpb.NewStringValue(roleArn),
			FieldProfileArn:     structpb.NewStringValue(profileArn),
		},
	}
}

// FromStruct extracts AWS RolesAnywhere ARNs from a structpb.Struct.
// The values are returned in the order trustAnchorArn, roleArn, profileArn.
func FromStruct(s *structpb.Struct) (string, string, string) {
	fields := s.GetFields()

	return fields[FieldTrustAnchorArn].GetStringValue(),
		fields[FieldRoleArn].GetStringValue(),
		fields[FieldProfileArn].GetStringValue()
}

package accessdata_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/internal/aws/accessdata"
)

func TestToStructFromStruct_RoundTrip(t *testing.T) {
	s := accessdata.ToStruct("trust-anchor", "role", "profile")

	assert.Equal(t, "trust-anchor", s.GetFields()[accessdata.FieldTrustAnchorArn].GetStringValue())
	assert.Equal(t, "role", s.GetFields()[accessdata.FieldRoleArn].GetStringValue())
	assert.Equal(t, "profile", s.GetFields()[accessdata.FieldProfileArn].GetStringValue())

	trustAnchorArn, roleArn, profileArn := accessdata.FromStruct(s)

	assert.Equal(t, "trust-anchor", trustAnchorArn)
	assert.Equal(t, "role", roleArn)
	assert.Equal(t, "profile", profileArn)
}

func TestFromStruct_Nil(t *testing.T) {
	trustAnchorArn, roleArn, profileArn := accessdata.FromStruct(nil)

	assert.Empty(t, trustAnchorArn)
	assert.Empty(t, roleArn)
	assert.Empty(t, profileArn)
}

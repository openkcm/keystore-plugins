package mutator_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/keystore-plugins/internal/utils/mutator"
)

type TestStruct struct {
	Field1 string
	Field2 int
}

func TestNewMutator(t *testing.T) {
	t.Parallel()

	baseProv := func() TestStruct {
		return TestStruct{
			Field1: "initial",
			Field2: 42,
		}
	}

	mut := mutator.NewMutator(baseProv)

	tests := []struct {
		name      string
		mutatorFn func(*TestStruct)
		expected  TestStruct
	}{
		{
			name:      "No mutation",
			mutatorFn: func(_ *TestStruct) {},
			expected: TestStruct{
				Field1: "initial",
				Field2: 42,
			},
		},
		{
			name: "Mutate Field1",
			mutatorFn: func(ts *TestStruct) {
				ts.Field1 = "mutated"
			},
			expected: TestStruct{
				Field1: "mutated",
				Field2: 42,
			},
		},
		{
			name: "Mutate Field2",
			mutatorFn: func(ts *TestStruct) {
				ts.Field2 = 100
			},
			expected: TestStruct{
				Field1: "initial",
				Field2: 100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := mut(tt.mutatorFn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

package must

// NotReturnError is a generic function that panics if the error is not nil.
//
//nolint:nolintlint,ireturn
func NotReturnError[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

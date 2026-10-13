package ptr

// PointTo creates a typed pointer of whatever you hand in as parameter
//
//go:fix inline
func PointTo[T any](t T) *T {
	return new(t)
}

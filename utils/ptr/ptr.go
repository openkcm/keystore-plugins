package ptr

// PointTo creates a typed pointer of whatever you hand in as parameter
func PointTo[T any](t T) *T {
	return &t
}

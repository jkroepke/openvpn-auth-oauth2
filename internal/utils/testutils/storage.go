package testutils

// FakeStorage is a no-op implementation of the token storage interface used in
// tests.
type FakeStorage struct{}

// NewFakeStorage returns a new FakeStorage instance.
func NewFakeStorage() *FakeStorage {
	return &FakeStorage{}
}

// Get returns an empty token.
func (FakeStorage) Get(_ string) (string, error) {
	return "", nil
}

// Close is a no-op for FakeStorage.
func (FakeStorage) Close() error {
	return nil
}

// Delete is a no-op for FakeStorage.
func (FakeStorage) Delete(_ string) error {
	return nil
}

// Set is a no-op for FakeStorage.
func (FakeStorage) Set(_, _ string) error {
	return nil
}

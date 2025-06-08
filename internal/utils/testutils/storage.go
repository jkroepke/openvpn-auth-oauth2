package testutils

type FakeStorage struct{}

func NewFakeStorage() *FakeStorage {
	return &FakeStorage{}
}

func (FakeStorage) Get(_ string) (string, error) {
	return "", nil
}

func (FakeStorage) Close() error {
	return nil
}

func (FakeStorage) Delete(_ string) error {
	return nil
}

func (FakeStorage) Set(_, _ string) error {
	return nil
}

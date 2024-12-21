package tokenstorage

type Storage interface {
	Get(client string) (string, error)
	Set(client string, token string) error
	Delete(client string)
}

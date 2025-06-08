package tokenstorage

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type File struct {
	file *os.File
	mu   sync.Mutex
	InMemory
}

func NewFile(filePath string, encryptionKey string, expires time.Duration) (*File, error) {
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0660)
	if err != nil {
		return nil, fmt.Errorf("open file error: %w", err)
	}

	data := make(dataMap)

	gob.Register(data)

	storage := &File{
		file: file,
		mu:   sync.Mutex{},
		InMemory: InMemory{
			data:          data,
			encryptionKey: encryptionKey,
			expires:       expires,
			mu:            sync.RWMutex{},
		},
	}

	if err := storage.load(); err != nil {
		_ = file.Close()

		return nil, fmt.Errorf("load data error: %w", err)
	}

	return storage, nil
}

func (s *File) Set(client, token string) error {
	if err := s.InMemory.Set(client, token); err != nil {
		return err
	}

	if err := s.writeToFile(); err != nil {
		return fmt.Errorf("write to file error: %w", err)
	}

	return nil
}

func (s *File) Delete(client string) error {
	if err := s.InMemory.Delete(client); err != nil {
		return err
	}

	if err := s.writeToFile(); err != nil {
		return fmt.Errorf("write to file error: %w", err)
	}

	return nil
}

func (s *File) Close() error {
	if s == nil {
		return nil
	}

	if err := s.writeToFile(); err != nil {
		return fmt.Errorf("write to file error: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.file.Close(); err != nil {
		return fmt.Errorf("close file error: %w", err)
	}

	s.file = nil

	return s.InMemory.Close()
}

func (s *File) writeToFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		return nil
	}

	// Reset file pointer to the beginning
	if _, err := s.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek file error: %w", err)
	}

	if err := gob.NewEncoder(s.file).Encode(s.data); err != nil {
		return fmt.Errorf("encode data error: %w", err)
	}

	return nil
}

func (s *File) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		return nil
	}

	if err := gob.NewDecoder(s.file).Decode(&s.data); err != nil && err != io.EOF {
		return fmt.Errorf("decode data error: %w", err)
	}

	return nil
}

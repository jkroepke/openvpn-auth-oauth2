package managementauth

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	passwordPrompt           = "ENTER PASSWORD:"
	badPasswordResponse      = "ERROR: bad password\r\n"
	passwordAcceptedResponse = "SUCCESS: password is correct\r\n"
)

// ErrInvalidPassword reports that a management client provided the wrong password.
var ErrInvalidPassword = errors.New("client provide invalid password")

// Authenticate validates an optional OpenVPN management password exchange.
func Authenticate(conn net.Conn, scanner *bufio.Scanner, password string, timeout time.Duration) error {
	if password == "" {
		return nil
	}

	if err := writeWithDeadline(conn, timeout, passwordPrompt); err != nil {
		return err
	}

	passwordLine, err := readPasswordLine(conn, scanner, timeout)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(passwordLine, []byte(password)) == 0 {
		_ = writeWithDeadline(conn, timeout, badPasswordResponse)

		return ErrInvalidPassword
	}

	return writeWithDeadline(conn, timeout, passwordAcceptedResponse)
}

func readPasswordLine(conn net.Conn, scanner *bufio.Scanner, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("unable to set read deadline: %w", err)
	}

	if !scanner.Scan() {
		err := scanner.Err()
		if err == nil {
			err = io.EOF
		}

		return nil, fmt.Errorf("unable to read from client: %w", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("unable to clear read deadline: %w", err)
	}

	return scanner.Bytes(), nil
}

func writeWithDeadline(conn net.Conn, timeout time.Duration, message string) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("unable to set write deadline: %w", err)
	}

	if _, err := conn.Write([]byte(message)); err != nil {
		return fmt.Errorf("unable to write to client: %w", err)
	}

	return nil
}

package main

import "C"
import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

const writeTimeout = 20 * time.Millisecond

type ManagementClient struct {
	logger       *slog.Logger
	password     string
	listenSocket net.Listener
	connection   net.Conn
	connectionMu sync.Mutex
	connected    atomic.Int64
}

func NewManagementClient(logger *slog.Logger, password string) *ManagementClient {
	return &ManagementClient{
		logger:   logger,
		password: password,
	}
}

func (m *ManagementClient) Listen(ctx context.Context, addr string) error {
	parsedURL, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("invalid listen socket address '%s': %w", addr, err)
	} else if parsedURL.Scheme != "tcp" && parsedURL.Scheme != "unix" {
		return fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	var lc net.ListenConfig

	m.listenSocket, err = lc.Listen(ctx, parsedURL.Scheme, parsedURL.Host)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		for {
			connection, err := m.listenSocket.Accept()
			if err != nil {
				m.logger.Warn(fmt.Errorf("error accepting: %w", err).Error())

				return
			}

			if err := m.handleClient(ctx, connection); err != nil {
				m.logger.Warn(fmt.Errorf("error handling client: %w", err).Error())
			}
		}
	}()

	return nil
}

func (m *ManagementClient) Close() {
	if m.listenSocket != nil {
		if err := m.listenSocket.Close(); err != nil {
			m.logger.Error(fmt.Errorf("unable to close listen socket: %w", err).Error())
		}
	}

	m.connectionMu.Lock()
	if m.connection != nil {
		if err := m.connection.Close(); err != nil {
			m.logger.Error(fmt.Errorf("unable to close connection: %w", err).Error())
		}
	}
	m.connectionMu.Unlock()
}

func (m *ManagementClient) handleClient(ctx context.Context, conn net.Conn) error {
	m.connectionMu.Lock()
	m.connection = conn
	m.connectionMu.Unlock()
	m.connected.Store(1)

	defer func() {
		m.connectionMu.Lock()
		m.connection = nil
		m.connectionMu.Unlock()
		m.connected.Store(0)
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	if err := m.handleClientAuth(ctx, conn, scanner); err != nil {
		return err
	}

	m.writeToClient(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	m.connected.Store(1)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "exit" {
			m.writeToClient("SUCCESS: exiting")
			break
		}

		m.writeToClient(fmt.Sprintf("UNKNOWN: %s", line))
	}

	if err := scanner.Err(); err != nil {
		if err == io.EOF {
			return nil
		} else {
			return err
		}
	}

	if err := conn.Close(); err != nil {
		return fmt.Errorf("unable to close connection: %w", err)
	}

	return nil
}

func (m *ManagementClient) handleClientAuth(_ context.Context, conn net.Conn, scanner *bufio.Scanner) error {
	if m.password == "" {
		return nil
	}

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("unable to set write deadline: %w", err)
	}

	_, err := conn.Write([]byte("ENTER PASSWORD:"))
	if err != nil {
		return fmt.Errorf("unable to write to client: %w", err)
	}

	if !scanner.Scan() {
		if err = scanner.Err(); err != nil {
			err = io.EOF
		}

		return fmt.Errorf("unable to read from client: %w", err)
	}

	if scanner.Text() != m.password {
		m.writeToClient("ERROR: bad password")

		return errors.New("client provide invalid password")
	}

	m.writeToClient("SUCCESS: password is correct")

	return nil
}

func (m *ManagementClient) writeToClient(message string) {
	m.connectionMu.Lock()
	defer m.connectionMu.Unlock()

	if m.connection == nil {
		return
	}

	if err := m.connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		m.logger.Error(fmt.Errorf("unable to set write deadline: %w", err).Error())

		return
	}

	if _, err := m.connection.Write([]byte(message + "\r\n")); err != nil {
		m.logger.Error(fmt.Errorf("unable to write to client: %w", err).Error())
	}
}

func (m *ManagementClient) SendClient(client Client) error {
	if m.connection == nil {
		return fmt.Errorf("no connection to client")
	}

	if err := m.connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("unable to set write deadline: %w", err)
	}

	if _, err := m.connection.Write([]byte(client.String())); err != nil {
		return fmt.Errorf("unable to write to client: %w", err)
	}

	return nil
}

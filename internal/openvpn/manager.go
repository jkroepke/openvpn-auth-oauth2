package openvpn

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// Manager manages multiple OpenVPN client connections
type Manager struct {
	clients    map[string]*Client
	clientsMu  sync.RWMutex
	logger     *slog.Logger
	conf       config.Config
	oauth2     oauth2Client
	httpClient *http.Client
}

// NewManager creates a new OpenVPN client manager
func NewManager(logger *slog.Logger, conf config.Config) *Manager {
	return &Manager{
		clients:   make(map[string]*Client),
		clientsMu: sync.RWMutex{},
		logger:    logger,
		conf:      conf,
	}
}

// SetOAuth2Client sets the OAuth2 client for all managed OpenVPN clients
func (m *Manager) SetOAuth2Client(client oauth2Client) {
	m.oauth2 = client
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()

	for _, openvpnClient := range m.clients {
		openvpnClient.SetOAuth2Client(client)
	}
}

// AddServer adds a new OpenVPN server to the manager
func (m *Manager) AddServer(serverName string, serverConf config.OpenVPNServer) error {
	m.clientsMu.Lock()
	defer m.clientsMu.Unlock()

	// Create individual config for this server
	serverConfig := m.createServerConfig(serverConf)

	client := New(m.logger, serverConfig)

	// Set OAuth2 client if available
	if m.oauth2 != nil {
		client.SetOAuth2Client(m.oauth2)
	}

	m.clients[serverName] = client

	m.logger.LogAttrs(context.Background(), slog.LevelInfo,
		"added OpenVPN server to manager",
		slog.String("server", serverName),
		slog.String("addr", serverConf.Addr.String()))

	return nil
}

// RemoveServer removes an OpenVPN server from the manager
func (m *Manager) RemoveServer(serverName string) error {
	m.clientsMu.Lock()
	defer m.clientsMu.Unlock()

	client, exists := m.clients[serverName]
	if !exists {
		return fmt.Errorf("server %s not found", serverName)
	}

	// Shutdown the client
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client.Shutdown(ctx)
	delete(m.clients, serverName)

	m.logger.LogAttrs(context.Background(), slog.LevelInfo,
		"removed OpenVPN server from manager",
		slog.String("server", serverName))

	return nil
}

// GetClient returns a specific OpenVPN client by server name
func (m *Manager) GetClient(serverName string) (*Client, bool) {
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()

	client, exists := m.clients[serverName]
	return client, exists
}

// GetAllClients returns all managed OpenVPN clients
func (m *Manager) GetAllClients() map[string]*Client {
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()

	// Return a copy to prevent external modification
	clients := make(map[string]*Client)
	for name, client := range m.clients {
		clients[name] = client
	}

	return clients
}

// ConnectAll connects to all managed OpenVPN servers
func (m *Manager) ConnectAll(ctx context.Context) error {
	m.clientsMu.RLock()
	clients := make(map[string]*Client)
	for name, client := range m.clients {
		clients[name] = client
	}
	m.clientsMu.RUnlock()

	if len(clients) == 0 {
		return fmt.Errorf("no OpenVPN servers configured")
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(clients))

	for name, client := range clients {
		wg.Add(1)
		go func(name string, client *Client) {
			defer wg.Done()

			m.logger.LogAttrs(ctx, slog.LevelInfo,
				"connecting to OpenVPN server",
				slog.String("server", name))

			if err := client.Connect(ctx); err != nil {
				errCh <- fmt.Errorf("server %s: %w", name, err)
				return
			}

			m.logger.LogAttrs(ctx, slog.LevelInfo,
				"successfully connected to OpenVPN server",
				slog.String("server", name))
		}(name, client)
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to connect to %d servers: %v", len(errors), errors)
	}

	return nil
}

// ShutdownAll gracefully shuts down all managed OpenVPN clients
func (m *Manager) ShutdownAll(ctx context.Context) {
	m.clientsMu.RLock()
	clients := make(map[string]*Client)
	for name, client := range m.clients {
		clients[name] = client
	}
	m.clientsMu.RUnlock()

	var wg sync.WaitGroup
	for name, client := range clients {
		wg.Add(1)
		go func(name string, client *Client) {
			defer wg.Done()

			m.logger.LogAttrs(ctx, slog.LevelInfo,
				"shutting down OpenVPN server connection",
				slog.String("server", name))

			client.Shutdown(ctx)
		}(name, client)
	}

	wg.Wait()
}

// GetServerStatus returns the status of all managed servers
func (m *Manager) GetServerStatus() map[string]ServerStatus {
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()

	status := make(map[string]ServerStatus)
	for name, client := range m.clients {
		status[name] = client.GetStatus()
	}

	return status
}

// AcceptClient routes the client acceptance to the correct OpenVPN server
func (m *Manager) AcceptClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, reAuth bool, username string) {
	// Extract server name from context or use default
	serverName := m.getServerNameFromContext(ctx)
	if serverName == "" {
		serverName = "default"
	}

	openvpnClient, exists := m.GetClient(serverName)
	if !exists {
		logger.LogAttrs(ctx, slog.LevelError, "OpenVPN server not found", slog.String("server", serverName))
		return
	}

	openvpnClient.AcceptClient(ctx, logger, client, reAuth, username)
}

// DenyClient routes the client denial to the correct OpenVPN server
func (m *Manager) DenyClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, reason string) {
	// Extract server name from context or use default
	serverName := m.getServerNameFromContext(ctx)
	if serverName == "" {
		serverName = "default"
	}

	openvpnClient, exists := m.GetClient(serverName)
	if !exists {
		logger.LogAttrs(ctx, slog.LevelError, "OpenVPN server not found", slog.String("server", serverName))
		return
	}

	openvpnClient.DenyClient(ctx, logger, client, reason)
}

// getServerNameFromContext extracts server name from context
func (m *Manager) getServerNameFromContext(ctx context.Context) string {
	if serverName, ok := ctx.Value("server_name").(string); ok {
		return serverName
	}
	return ""
}

// SetServerNameInContext adds server name to context
func (m *Manager) SetServerNameInContext(ctx context.Context, serverName string) context.Context {
	return context.WithValue(ctx, "server_name", serverName)
}

// createServerConfig creates a server-specific configuration
func (m *Manager) createServerConfig(serverConf config.OpenVPNServer) config.Config {
	serverConfig := m.conf
	serverConfig.OpenVPN = config.OpenVPN{
		Addr:               serverConf.Addr,
		Password:           serverConf.Password,
		ClientConfig:       m.conf.OpenVPN.ClientConfig,
		Bypass:             m.conf.OpenVPN.Bypass,
		CommonName:         m.conf.OpenVPN.CommonName,
		Passthrough:        m.conf.OpenVPN.Passthrough,
		AuthPendingTimeout: m.conf.OpenVPN.AuthPendingTimeout,
		CommandTimeout:     m.conf.OpenVPN.CommandTimeout,
		AuthTokenUser:      m.conf.OpenVPN.AuthTokenUser,
		OverrideUsername:   m.conf.OpenVPN.OverrideUsername,
		ReAuthentication:   m.conf.OpenVPN.ReAuthentication,
	}

	return serverConfig
}

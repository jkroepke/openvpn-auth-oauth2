package openvpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
)

const clientKillMissingResponse = "ERROR: client-kill command failed"

func (c *Client) enforceUniqueUser(ctx context.Context, logger *slog.Logger, currentCID uint64, username string) error {
	if username == "" {
		return errors.New("cannot enforce a single active session: username is empty")
	}

	status, err := c.SendCommand(ctx, "status 3", false)
	if err != nil {
		return fmt.Errorf("query OpenVPN status: %w", err)
	}

	if strings.HasPrefix(status, "ERROR:") {
		return fmt.Errorf("query OpenVPN status: %w: %s", ErrErrorResponse, strings.TrimSpace(status))
	}

	clientIDs, err := statusClientIDsByUsername(status, username, currentCID)
	if err != nil {
		return fmt.Errorf("parse OpenVPN status: %w", err)
	}

	for _, clientID := range clientIDs {
		logger.LogAttrs(
			ctx, slog.LevelInfo, "terminate existing OpenVPN session",
			slog.String("user_username", username),
			slog.Uint64("existing_cid", clientID),
		)

		response, err := c.SendCommandf(ctx, "client-kill %d", clientID)
		if err != nil {
			return fmt.Errorf("terminate OpenVPN client %d: %w", clientID, err)
		}

		response = strings.TrimSpace(response)
		if response == clientKillMissingResponse {
			logger.LogAttrs(
				ctx, slog.LevelDebug, "existing OpenVPN session already terminated",
				slog.Uint64("existing_cid", clientID),
			)

			continue
		}

		if strings.HasPrefix(response, "ERROR:") {
			return fmt.Errorf("terminate OpenVPN client %d: %w: %s", clientID, ErrErrorResponse, response)
		}
	}

	return nil
}

func statusClientIDsByUsername(status, username string, currentCID uint64) ([]uint64, error) {
	usernameIndex, clientIDIndex, err := statusClientListColumns(status)
	if err != nil {
		return nil, err
	}

	clientIDs := make([]uint64, 0)
	seenClientIDs := make(map[uint64]struct{})

	for line := range strings.SplitSeq(status, "\n") {
		fields := strings.Split(strings.TrimSuffix(line, "\r"), "\t")
		if len(fields) == 0 || fields[0] != "CLIENT_LIST" {
			continue
		}

		clientID, matches, err := statusClientID(fields, usernameIndex, clientIDIndex, username, currentCID)
		if err != nil {
			return nil, err
		}

		if !matches {
			continue
		}

		if _, ok := seenClientIDs[clientID]; ok {
			continue
		}

		seenClientIDs[clientID] = struct{}{}
		clientIDs = append(clientIDs, clientID)
	}

	return clientIDs, nil
}

func statusClientListColumns(status string) (int, int, error) {
	for line := range strings.SplitSeq(status, "\n") {
		fields := strings.Split(strings.TrimSuffix(line, "\r"), "\t")
		if len(fields) < 2 || fields[0] != "HEADER" || fields[1] != "CLIENT_LIST" {
			continue
		}

		var (
			usernameIndex = slices.Index(fields, "Username") - 1
			clientIDIndex = slices.Index(fields, "Client ID") - 1
		)
		if usernameIndex < 0 || clientIDIndex < 0 {
			break
		}

		return usernameIndex, clientIDIndex, nil
	}

	return 0, 0, errors.New("client list header is missing Username or Client ID")
}

func statusClientID(fields []string, usernameIndex, clientIDIndex int, username string, currentCID uint64) (uint64, bool, error) {
	if usernameIndex >= len(fields) || clientIDIndex >= len(fields) {
		return 0, false, fmt.Errorf(
			"client list record has %d fields, expected at least %d",
			len(fields),
			max(usernameIndex, clientIDIndex)+1,
		)
	}

	if fields[usernameIndex] != username {
		return 0, false, nil
	}

	clientID, err := strconv.ParseUint(fields[clientIDIndex], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse client list client ID %q: %w", fields[clientIDIndex], err)
	}

	return clientID, clientID != currentCID, nil
}

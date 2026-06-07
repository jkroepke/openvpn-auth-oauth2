package testsuite

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/stretchr/testify/require"
)

type Conn struct {
	conn   net.Conn
	reader *bufio.Reader
	logs   func() string
}

func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (c *Conn) WithLogs(logs func() string) *Conn {
	c.logs = logs

	return c
}

func (c *Conn) SendAndExpectMessage(tb testing.TB, sendMessage, expectMessage string) {
	tb.Helper()

	c.SendMessagef(tb, sendMessage)
	c.ExpectMessage(tb, expectMessage)
}

func (c *Conn) SendMessagef(tb testing.TB, sendMessage string, args ...any) {
	tb.Helper()

	sendMessagef(tb, c.conn, c.logs, sendMessage, args...)
}

func (c *Conn) ExpectMessage(tb testing.TB, expectMessage string) {
	tb.Helper()

	expectConnMessage(tb, c.conn, c.reader, c.logs, expectMessage)
}

func (c *Conn) ExpectVersionAndReleaseHold(tb testing.TB) {
	tb.Helper()

	expectVersionAndReleaseHold(tb, c.conn, c.reader, c.logs)
}

func (c *Conn) ReadLine(tb testing.TB) string {
	tb.Helper()

	return readLine(tb, c.conn, c.reader)
}

func (c *Conn) Reader() *bufio.Reader {
	return c.reader
}

func sendMessagef(tb testing.TB, conn net.Conn, logs func() string, sendMessage string, args ...any) {
	tb.Helper()

	require.NotNil(tb, conn, "connection is nil\n\n%s", logOutput(logs))
	require.NoError(tb, conn.SetWriteDeadline(time.Now().Add(time.Second*5)))

	if sendMessage != "ENTER PASSWORD:" {
		sendMessage += "\r\n"
	}

	_, err := fmt.Fprintf(conn, sendMessage, args...)
	require.NoError(tb, err, "error sending message to management interface\n\n%s", logOutput(logs))
}

func expectConnMessage(tb testing.TB, conn net.Conn, reader *bufio.Reader, logs func() string, expectMessage string) {
	tb.Helper()

	var (
		err  error
		line string
	)
	for expected := range strings.SplitSeq(strings.TrimSpace(expectMessage), "\n") {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		require.NoError(tb, err, "expected line: %s\nexpected message:\n%s\n\n%s", expected, expectMessage, logOutput(logs))

		line, err = reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			require.NoError(tb, err, "expected line: %s\nexpected message:\n%s\n\n%s", expected, expectMessage, logOutput(logs))
		}

		require.Equal(tb, strings.TrimRightFunc(expected, unicode.IsSpace), strings.TrimRightFunc(line, unicode.IsSpace), logOutput(logs))
	}
}

func expectVersionAndReleaseHold(tb testing.TB, conn net.Conn, reader *bufio.Reader, logs func() string) {
	tb.Helper()

	sendMessagef(tb, conn, logs, openvpn.WelcomeBanner)
	sendMessagef(tb, conn, logs, ">HOLD:Waiting for hold release:0")

	var expectedCommand int

	for range 2 {
		line := readLine(tb, conn, reader)
		switch line {
		case ManagementCommandHold:
			sendMessagef(tb, conn, logs, "SUCCESS: hold release succeeded")

			expectedCommand++
		case ManagementCommandVersion:
			sendMessagef(tb, conn, logs, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND")

			expectedCommand++
		default:
			require.Contains(tb, []string{ManagementCommandVersion, ManagementCommandHold}, line)
		}
	}

	require.Equal(tb, 2, expectedCommand)
}

func readLine(tb testing.TB, conn net.Conn, reader *bufio.Reader) string {
	tb.Helper()

	err := conn.SetReadDeadline(time.Now().Add(time.Second * 50))
	require.NoError(tb, err)

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		require.NoError(tb, err)
	}

	return strings.TrimRightFunc(line, unicode.IsSpace)
}

func logOutput(logs func() string) string {
	if logs == nil {
		return ""
	}

	return logs()
}

package mi

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// SendCommand passes command to a given connection (adds logging and EOL character)
func SendCommand(conn net.Conn, cmd string) error {
	if _, err := fmt.Fprintf(conn, cmd+"\n"); err != nil {
		return err
	}
	return nil
}

// ReadResponse .
func ReadResponse(reader *bufio.Reader) (string, error) {
	var finished = false
	var result = ""
	i := 0

	for finished == false {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Error(line, err)
			return "", err
		}

		result += line
		if strings.Index(line, "END") == 0 ||
			strings.Index(line, "SUCCESS:") == 0 ||
			strings.Index(line, "ERROR:") == 0 {
			finished = true
		}
		i++
	}
	return result, nil
}

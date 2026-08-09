// container-healthcheck is a dependency-free health probe for RustyAuth's
// scratch runtime images. Keeping the probe in the image avoids adding a shell,
// curl, wget, or a package manager solely for Docker health checks.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const probeTimeout = 2 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "redis" {
		return checkRedis(args[1])
	}
	if len(args) == 3 && args[0] == "http" {
		return checkHTTP(args[1], args[2])
	}
	return errors.New("usage: container-healthcheck redis HOST:PORT | http HOST:PORT /PATH")
}

func dial(address string) (net.Conn, error) {
	connection, err := net.DialTimeout("tcp", address, probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to health endpoint: %w", err)
	}
	if err := connection.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		connection.Close()
		return nil, fmt.Errorf("bound health-check deadline: %w", err)
	}
	return connection, nil
}

func checkRedis(address string) error {
	connection, err := dial(address)
	if err != nil {
		return err
	}
	defer connection.Close()

	if _, err := io.WriteString(connection, "*1\r\n$4\r\nPING\r\n"); err != nil {
		return fmt.Errorf("write Redis PING: %w", err)
	}
	reply, err := bufio.NewReader(io.LimitReader(connection, 64)).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read Redis PING response: %w", err)
	}
	if reply != "+PONG\r\n" {
		return errors.New("Redis health endpoint returned an unexpected response")
	}
	return nil
}

func checkHTTP(address, path string) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return errors.New("HTTP health-check path must be an absolute path without control characters")
	}
	connection, err := dial(address)
	if err != nil {
		return err
	}
	defer connection.Close()

	request := "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		return fmt.Errorf("write HTTP health request: %w", err)
	}
	status, err := bufio.NewReader(io.LimitReader(connection, 4*1024)).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read HTTP health response: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200 ") && !strings.HasPrefix(status, "HTTP/1.0 200 ") {
		return errors.New("HTTP health endpoint returned a non-200 status")
	}
	return nil
}

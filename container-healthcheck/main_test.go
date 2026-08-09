package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRedisProbeRequiresPong(t *testing.T) {
	address, stop := serveOnce(t, func(connection net.Conn) {
		request := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
		if _, err := io.ReadFull(connection, request); err != nil {
			t.Errorf("read probe: %v", err)
			return
		}
		if string(request) != "*1\r\n$4\r\nPING\r\n" {
			t.Errorf("unexpected probe %q", request)
			return
		}
		_, _ = io.WriteString(connection, "+PONG\r\n")
	})
	defer stop()

	if err := checkRedis(address); err != nil {
		t.Fatalf("Redis probe failed: %v", err)
	}
}

func TestRedisProbeRejectsUnexpectedResponse(t *testing.T) {
	address, stop := serveOnce(t, func(connection net.Conn) {
		_, _ = bufio.NewReader(connection).ReadString('\n')
		_, _ = io.WriteString(connection, "-ERR unavailable\r\n")
	})
	defer stop()

	if err := checkRedis(address); err == nil {
		t.Fatal("unexpected Redis response was accepted")
	}
}

func TestHTTPProbeRequiresSuccessfulStatus(t *testing.T) {
	address, stop := serveOnce(t, func(connection net.Conn) {
		request, _ := bufio.NewReader(connection).ReadString('\n')
		if request != "GET /healthz HTTP/1.1\r\n" {
			t.Errorf("unexpected request line %q", request)
		}
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	defer stop()

	if err := checkHTTP(address, "/healthz"); err != nil {
		t.Fatalf("HTTP probe failed: %v", err)
	}
}

func TestHTTPProbeRejectsFailuresAndInvalidPaths(t *testing.T) {
	address, stop := serveOnce(t, func(connection net.Conn) {
		_, _ = bufio.NewReader(connection).ReadString('\n')
		_, _ = io.WriteString(connection, "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
	})
	defer stop()

	if err := checkHTTP(address, "/readyz"); err == nil {
		t.Fatal("non-200 HTTP status was accepted")
	}
	if err := checkHTTP(address, "relative"); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("invalid path error = %v", err)
	}
}

func TestRunRejectsUnknownInvocation(t *testing.T) {
	if err := run([]string{"tcp", "localhost:1"}); err == nil {
		t.Fatal("unknown probe mode was accepted")
	}
}

func serveOnce(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		handler(connection)
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("health-check fixture did not stop")
		}
	}
}

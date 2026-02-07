package socks

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func (m *MockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *MockConn) Close() error                       { return nil }
func (m *MockConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, _ := l.Accept()
		defer conn.Close()

		buf := make([]byte, 4)
		io.ReadAtLeast(conn, buf, 4)

		bytes.Equal(buf, []byte("ping"))
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf, socks5Version)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, _ := l.Accept()
		defer conn.Close()

		buf := make([]byte, 4)
		io.ReadAtLeast(conn, buf, 4)

		bytes.Equal(buf, []byte("ping"))
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   log.New(os.Stdout, "", log.LstdFlags),
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf, socks5Version)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestHandleAssociate_Closure(t *testing.T) {
	s, _ := New(&Config{})

	// Create a pipe to simulate a connection
	client, server := net.Pipe()

	req := &Request{
		Version: socks5Version,
		Command: AssociateCommand,
		DestAddr: &AddrSpec{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.handleAssociate(context.Background(), server, req)
	}()

	// Wait for the server to send the success reply
	reply := make([]byte, 10)
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := client.Read(reply)
	if err != nil {
		t.Fatalf("failed to read reply: %v", err)
	}
	if reply[1] != successReply {
		t.Fatalf("expected success reply, got %v", reply[1])
	}

	// The server should now be blocking in handleAssociate
	select {
	case err := <-errCh:
		t.Fatalf("handleAssociate returned prematurely: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Success, it's still blocking
	}

	// Now close the client connection
	client.Close()

	// handleAssociate should now return
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleAssociate returned error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("handleAssociate did not return after client closure")
	}
}

func TestHandleAssociate_WithData(t *testing.T) {
	s, _ := New(&Config{})

	client, server := net.Pipe()

	req := &Request{
		Version: socks5Version,
		Command: AssociateCommand,
		DestAddr: &AddrSpec{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.handleAssociate(context.Background(), server, req)
	}()

	// Read reply
	reply := make([]byte, 10)
	client.Read(reply)

	// Send some data from client (which it shouldn't, but we should handle it)
	go func() {
		client.Write([]byte("some data"))
		time.Sleep(50 * time.Millisecond)
		client.Close()
	}()

	// handleAssociate should still return only after closure
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handleAssociate returned error: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("handleAssociate did not return after client closure")
	}
}

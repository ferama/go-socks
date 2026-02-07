package socks

import (
	"bytes"
	"testing"
)

func TestSOCKS4a_Address_Handling(t *testing.T) {
	// SOCKS 4a request: VN=4, CD=1, Port=80, IP=0.0.0.1, User="tom", Null, Host="google.com", Null
	requestData := []byte{
		4, 1,
		0, 80,
		0, 0, 0, 1,
		't', 'o', 'm', 0,
		'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0,
	}
	reader := bytes.NewReader(requestData[1:]) // skip version byte

	req, err := NewRequest(reader, 4)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	if req.DestAddr.FQDN != "google.com" {
		t.Errorf("Expected FQDN google.com, got %s", req.DestAddr.FQDN)
	}

	expectedAddr := "google.com:80"
	if addr := req.DestAddr.Address(); addr != expectedAddr {
		t.Errorf("Expected Address() to be %s, got %s", expectedAddr, addr)
	}
}

func TestSOCKS4_Connect_Request(t *testing.T) {
	// SOCKS 4 request: VN=4, CD=1, Port=443, IP=1.2.3.4, User="alice", Null
	requestData := []byte{
		4, 1,
		1, 187,
		1, 2, 3, 4,
		'a', 'l', 'i', 'c', 'e', 0,
	}
	reader := bytes.NewReader(requestData[1:]) // skip version byte

	req, err := NewRequest(reader, 4)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	if req.DestAddr.IP.String() != "1.2.3.4" {
		t.Errorf("Expected IP 1.2.3.4, got %s", req.DestAddr.IP)
	}

	if req.DestAddr.Port != 443 {
		t.Errorf("Expected Port 443, got %d", req.DestAddr.Port)
	}

	if req.AuthContext.Payload["Username"] != "alice" {
		t.Errorf("Expected Username alice, got %s", req.AuthContext.Payload["Username"])
	}
}

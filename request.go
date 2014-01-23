package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	connectCommand   = uint8(1)
	bindCommand      = uint8(2)
	associateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = 0
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// addrSpec is used to return the target addrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type addrSpec struct {
	fqdn string
	ip   net.IP
	port int
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(conn io.Writer, bufConn io.Reader) error {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Switch on the command
	switch header[1] {
	case connectCommand:
		return s.handleConnect(conn, bufConn, dest)
	case bindCommand:
		return s.handleBind(conn, bufConn, dest)
	case associateCommand:
		return s.handleAssociate(conn, bufConn, dest)
	default:
		return fmt.Errorf("Unsupported command: %v", header[1])
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(conn io.Writer, bufConn io.Reader, dest *addrSpec) error {
	return nil
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(conn io.Writer, bufConn io.Reader, dest *addrSpec) error {
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(conn io.Writer, bufConn io.Reader, dest *addrSpec) error {
	return nil
}

// readAddrSpec is used to read addrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*addrSpec, error) {
	d := &addrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.ip = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.ip = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.fqdn = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.port = int(binary.BigEndian.Uint16(port))

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *addrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	switch {
	case addr == nil:
		addrType = 0
		addrBody = nil

	case addr.fqdn != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.fqdn))}, addr.fqdn...)

	case addr.ip.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.ip.To4())

	case addr.ip.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.ip.To16())

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	binary.BigEndian.PutUint16(msg[4+len(addrBody):], uint16(addr.port))

	// Send the message
	_, err := w.Write(msg)
	return err
}
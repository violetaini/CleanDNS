package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestBuildProxyV2HeaderIPv4(t *testing.T) {
	header, err := buildProxyV2Header(
		&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 53001},
		&net.UDPAddr{IP: net.ParseIP("192.0.2.8"), Port: 5642},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := header[13]; got != 0x12 {
		t.Fatalf("family/protocol = %#x, want IPv4 datagram", got)
	}
	if got := net.IP(header[16:20]).String(); got != "203.0.113.7" {
		t.Fatalf("source IP = %s", got)
	}
	if got := binary.BigEndian.Uint16(header[24:26]); got != 53001 {
		t.Fatalf("source port = %d", got)
	}
	if got := header[28:]; !bytes.Equal(got, []byte{0x01, 0x00, 0x03, 'd', 'o', 'q'}) {
		t.Fatalf("ALPN TLV = %x", got)
	}
}

func TestBuildProxyV2HeaderIPv6(t *testing.T) {
	header, err := buildProxyV2Header(
		&net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 53002},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::8"), Port: 5642},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := header[13]; got != 0x22 {
		t.Fatalf("family/protocol = %#x, want IPv6 datagram", got)
	}
	if got := net.IP(header[16:32]).String(); got != "2001:db8::7" {
		t.Fatalf("source IP = %s", got)
	}
	if got := binary.BigEndian.Uint16(header[48:50]); got != 53002 {
		t.Fatalf("source port = %d", got)
	}
	if got := header[52:]; !bytes.Equal(got, []byte{0x01, 0x00, 0x03, 'd', 'o', 'q'}) {
		t.Fatalf("ALPN TLV = %x", got)
	}
}

func TestReadDoQMessageRejectsProtocolViolations(t *testing.T) {
	tests := map[string][]byte{
		"short message": {0x00, 0x0b, 0x00, 0x00},
		"nonzero id":    append([]byte{0x00, 0x0c}, []byte{0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}...),
		"second message": append(
			append([]byte{0x00, 0x0c}, testDNSQuery()...),
			0x00,
		),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := readDoQMessage(bytes.NewReader(input))
			var violation *protocolViolation
			if !errors.As(err, &violation) {
				t.Fatalf("error = %v, want protocol violation", err)
			}
		})
	}
}

func TestForwardDNSPreservesDoQClientMetadata(t *testing.T) {
	core, requests := startTestCore(t)
	server := &doqServer{
		upstream: core.LocalAddr().(*net.UDPAddr),
		timeout:  time.Second,
	}
	query := testDNSQuery()
	response, err := server.forwardDNS(
		query,
		&net.UDPAddr{IP: net.ParseIP("198.51.100.42"), Port: 49152},
		&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5642},
	)
	if err != nil {
		t.Fatal(err)
	}
	if response[0] != 0 || response[1] != 0 || response[2]&0x80 == 0 {
		t.Fatalf("invalid DNS response header: %x", response[:4])
	}

	select {
	case packet := <-requests:
		if packet[13] != 0x12 {
			t.Fatalf("family/protocol = %#x", packet[13])
		}
		if got := net.IP(packet[16:20]).String(); got != "198.51.100.42" {
			t.Fatalf("source IP = %s", got)
		}
		proxyLength := int(binary.BigEndian.Uint16(packet[14:16]))
		if got := packet[16+proxyLength:]; !bytes.Equal(got, query) {
			t.Fatalf("forwarded DNS query mismatch: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("CleanDNS core did not receive query")
	}
}

func TestDoQServerRoundTrip(t *testing.T) {
	core, requests := startTestCore(t)
	serverTLS := testTLSConfig(t)
	server, err := newDoQServer("127.0.0.1:0", serverTLS, core.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})

	client, err := quic.DialAddr(context.Background(), server.listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{doqALPN},
	}, &quic.Config{HandshakeIdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(doqNoError, "")

	stream, err := client.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	query := testDNSQuery()
	if err = writeDoQMessage(stream, query); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := readDoQMessage(stream)
	if err != nil {
		t.Fatal(err)
	}
	if response[2]&0x80 == 0 {
		t.Fatalf("response does not have QR bit: %x", response[:4])
	}

	select {
	case packet := <-requests:
		proxyLength := int(binary.BigEndian.Uint16(packet[14:16]))
		if !bytes.Equal(packet[16+proxyLength:], query) {
			t.Fatal("round-trip query did not reach CleanDNS core")
		}
	case <-time.After(time.Second):
		t.Fatal("round-trip query was not forwarded")
	}
}

func TestDoQServerConcurrentQueries(t *testing.T) {
	core, _ := startTestCore(t)
	server, err := newDoQServer("127.0.0.1:0", testTLSConfig(t), core.LocalAddr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	}()

	client, err := quic.DialAddr(context.Background(), server.listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{doqALPN},
	}, &quic.Config{HandshakeIdleTimeout: time.Second, MaxIncomingStreams: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(doqNoError, "")

	const queryCount = 128
	errorsCh := make(chan error, queryCount)
	var workers sync.WaitGroup
	for i := 0; i < queryCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			streamCtx, streamCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer streamCancel()
			stream, streamErr := client.OpenStreamSync(streamCtx)
			if streamErr != nil {
				errorsCh <- streamErr
				return
			}
			if streamErr = writeDoQMessage(stream, testDNSQuery()); streamErr == nil {
				streamErr = stream.Close()
			}
			var response []byte
			if streamErr == nil {
				response, streamErr = readDoQMessage(stream)
			}
			if streamErr == nil && response[2]&0x80 == 0 {
				streamErr = errors.New("response does not have QR bit")
			}
			if streamErr != nil {
				errorsCh <- streamErr
			}
		}()
	}
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent DoQ query: %v", err)
	}
}

func TestDoQServerClosesConnectionForNonzeroMessageID(t *testing.T) {
	core, _ := startTestCore(t)
	server, err := newDoQServer("127.0.0.1:0", testTLSConfig(t), core.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	}()

	client, err := quic.DialAddr(context.Background(), server.listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{doqALPN},
	}, &quic.Config{HandshakeIdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	query := testDNSQuery()
	query[0], query[1] = 0x12, 0x34
	if err = writeDoQMessage(stream, query); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(stream)
	var appError *quic.ApplicationError
	if !errors.As(err, &appError) || appError.ErrorCode != doqProtocolError {
		t.Fatalf("read error = %v, want DOQ_PROTOCOL_ERROR", err)
	}
}

func TestExternalDoQEndpoint(t *testing.T) {
	endpoint := os.Getenv("CLEANDNS_DOQ_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("CLEANDNS_DOQ_TEST_ENDPOINT is not set")
	}
	serverName := os.Getenv("CLEANDNS_DOQ_TEST_SERVER_NAME")
	if serverName == "" {
		var err error
		serverName, _, err = net.SplitHostPort(endpoint)
		if err != nil {
			t.Fatalf("parse endpoint: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, endpoint, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{doqALPN},
	}, &quic.Config{HandshakeIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(doqNoError, "")

	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = writeDoQMessage(stream, testDNSQuery()); err == nil {
		err = stream.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	response, err := readDoQMessage(stream)
	if err != nil {
		t.Fatal(err)
	}
	if response[2]&0x80 == 0 || response[3]&0x0f != 0 {
		t.Fatalf("unexpected DNS response header: %x", response[:4])
	}
}

func startTestCore(t *testing.T) (*net.UDPConn, <-chan []byte) {
	t.Helper()
	core, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Close() })
	requests := make(chan []byte, 256)
	go func() {
		buffer := make([]byte, maxProxyDatagramSize)
		for {
			n, peer, readErr := core.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			requests <- packet
			if len(packet) < 16 {
				continue
			}
			offset := 16 + int(binary.BigEndian.Uint16(packet[14:16]))
			if offset+12 > len(packet) {
				continue
			}
			response := append([]byte(nil), packet[offset:]...)
			response[2] |= 0x80
			_, _ = core.WriteToUDP(response, peer)
		}
	}()
	return core, requests
}

func testDNSQuery() []byte {
	return []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{doqALPN},
	}
}

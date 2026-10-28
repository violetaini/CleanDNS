package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	doqALPN              = "doq"
	maxDNSMessageSize    = 65535
	maxProxyDatagramSize = 65507

	doqNoError          quic.ApplicationErrorCode = 0x0
	doqInternalError    quic.ApplicationErrorCode = 0x1
	doqProtocolError    quic.ApplicationErrorCode = 0x2
	doqRequestCancelled quic.ApplicationErrorCode = 0x3
	doqExcessiveLoad    quic.ApplicationErrorCode = 0x4
)

var proxyV2Signature = [...]byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

type configFile struct {
	UDP struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"udp"`
	Service struct {
		DoQPort        int    `json:"doqPort"`
		DoQTLSCertFile string `json:"doqTlsCertFile"`
		DoQTLSKeyFile  string `json:"doqTlsKeyFile"`
	} `json:"service"`
	TimeoutMs int `json:"timeoutMs"`
}

type doqServer struct {
	listener *quic.Listener
	upstream *net.UDPAddr
	timeout  time.Duration

	mu            sync.Mutex
	connections   map[*quic.Conn]struct{}
	connectionsWG sync.WaitGroup
}

type protocolViolation struct {
	reason string
}

func (e *protocolViolation) Error() string {
	return e.reason
}

func main() {
	mode := flag.String("mode", "server", "runtime mode: server or upstream-stdio")
	configPath := flag.String("config", "/opt/cleandns/config.json", "CleanDNS config file")
	listen := flag.String("listen", "0.0.0.0", "DoQ listen address")
	flag.Parse()
	if *mode == "upstream-stdio" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			_ = os.Stdin.Close()
		}()
		if err := runDoQUpstreamStdio(ctx, os.Stdin, os.Stdout, nil); err != nil && ctx.Err() == nil {
			log.Fatalf("serve DoQ upstream bridge: %v", err)
		}
		return
	}
	if *mode != "server" {
		log.Fatalf("unsupported runtime mode %q", *mode)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	doqPort := cfg.Service.DoQPort
	if doqPort == 0 {
		doqPort = 853
	}
	certFile := firstNonEmpty(cfg.Service.DoQTLSCertFile, "/etc/cleandns/tls/fullchain.pem")
	keyFile := firstNonEmpty(cfg.Service.DoQTLSKeyFile, "/etc/cleandns/tls/privkey.pem")
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	udpHost := firstNonEmpty(cfg.UDP.Host, "127.0.0.1")
	udpPort := cfg.UDP.Port
	if udpPort == 0 {
		udpPort = 8053
	}
	upstreamAddr := net.JoinHostPort(udpHost, fmt.Sprint(udpPort))

	tlsConfig, err := makeTLSConfig(certFile, keyFile)
	if err != nil {
		log.Fatalf("load tls certificate: %v", err)
	}

	server, err := newDoQServer(net.JoinHostPort(*listen, fmt.Sprint(doqPort)), tlsConfig, upstreamAddr, timeout)
	if err != nil {
		log.Fatalf("start CleanDNS DoQ transport: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("cleandns-dns doq listening on %s, transport=quic-go, core=%s", server.listener.Addr(), upstreamAddr)
	if err = server.Serve(ctx); err != nil {
		log.Fatalf("serve CleanDNS DoQ transport: %v", err)
	}
	log.Print("stopped cleandns-dns")
}

func newDoQServer(listenAddr string, tlsConfig *tls.Config, upstreamAddr string, timeout time.Duration) (*doqServer, error) {
	upstream, err := net.ResolveUDPAddr("udp", upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve CleanDNS core %q: %w", upstreamAddr, err)
	}
	listener, err := quic.ListenAddr(listenAddr, tlsConfig, &quic.Config{
		HandshakeIdleTimeout:           5 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     128 * 1024,
		MaxStreamReceiveWindow:         128 * 1024,
		InitialConnectionReceiveWindow: 1024 * 1024,
		MaxConnectionReceiveWindow:     4 * 1024 * 1024,
		MaxIncomingStreams:             256,
		MaxIncomingUniStreams:          1,
		Allow0RTT:                      false,
	})
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	return &doqServer{
		listener:    listener,
		upstream:    upstream,
		timeout:     timeout,
		connections: make(map[*quic.Conn]struct{}),
	}, nil
}

func (s *doqServer) Serve(ctx context.Context) error {
	acceptDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-acceptDone:
		}
	}()

	var serveErr error
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, quic.ErrServerClosed) {
				serveErr = err
			}
			break
		}
		s.mu.Lock()
		s.connections[conn] = struct{}{}
		s.connectionsWG.Add(1)
		s.mu.Unlock()
		go s.serveConnection(ctx, conn)
	}

	close(acceptDone)
	s.closeConnections(doqNoError, "server shutdown")
	s.connectionsWG.Wait()
	return serveErr
}

func (s *doqServer) serveConnection(ctx context.Context, conn *quic.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
		s.connectionsWG.Done()
	}()

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		stream, err := conn.AcceptUniStream(connCtx)
		if err != nil {
			return
		}
		stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
		_ = conn.CloseWithError(doqProtocolError, "unidirectional streams are not allowed")
	}()

	var streams sync.WaitGroup
	for {
		stream, err := conn.AcceptStream(connCtx)
		if err != nil {
			break
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			s.serveStream(conn, stream)
		}()
	}
	cancel()
	streams.Wait()
}

func (s *doqServer) serveStream(conn *quic.Conn, stream *quic.Stream) {
	_ = stream.SetDeadline(time.Now().Add(s.timeout))
	query, err := readDoQMessage(stream)
	if err != nil {
		var violation *protocolViolation
		switch {
		case errors.As(err, &violation):
			_ = conn.CloseWithError(doqProtocolError, violation.Error())
		case isTimeout(err):
			stream.CancelRead(quic.StreamErrorCode(doqExcessiveLoad))
			stream.CancelWrite(quic.StreamErrorCode(doqExcessiveLoad))
		default:
			stream.CancelRead(quic.StreamErrorCode(doqRequestCancelled))
			stream.CancelWrite(quic.StreamErrorCode(doqRequestCancelled))
		}
		return
	}

	response, err := s.forwardDNS(query, conn.RemoteAddr(), conn.LocalAddr())
	if err != nil {
		log.Printf("doq core query failed for %s: %v", conn.RemoteAddr(), err)
		stream.CancelWrite(quic.StreamErrorCode(doqInternalError))
		return
	}
	if err = writeDoQMessage(stream, response); err != nil {
		stream.CancelWrite(quic.StreamErrorCode(doqRequestCancelled))
		return
	}
	_ = stream.Close()
}

func (s *doqServer) forwardDNS(query []byte, sourceAddr, destinationAddr net.Addr) ([]byte, error) {
	header, err := buildProxyV2Header(sourceAddr, destinationAddr)
	if err != nil {
		return nil, err
	}
	if len(header)+len(query) > maxProxyDatagramSize {
		return nil, fmt.Errorf("DNS query exceeds internal UDP transport limit")
	}

	network := "udp4"
	if s.upstream.IP.To4() == nil {
		network = "udp6"
	}
	core, err := net.DialUDP(network, nil, s.upstream)
	if err != nil {
		return nil, fmt.Errorf("connect CleanDNS core: %w", err)
	}
	defer core.Close()
	if err = core.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, err
	}

	packet := make([]byte, 0, len(header)+len(query))
	packet = append(packet, header...)
	packet = append(packet, query...)
	if _, err = core.Write(packet); err != nil {
		return nil, fmt.Errorf("write CleanDNS core query: %w", err)
	}

	response := make([]byte, maxDNSMessageSize)
	n, err := core.Read(response)
	if err != nil {
		return nil, fmt.Errorf("read CleanDNS core response: %w", err)
	}
	if n < 12 {
		return nil, fmt.Errorf("CleanDNS core returned a short DNS response")
	}
	response = response[:n]
	response[0], response[1] = 0, 0
	return response, nil
}

func (s *doqServer) closeConnections(code quic.ApplicationErrorCode, reason string) {
	s.mu.Lock()
	connections := make([]*quic.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	for _, conn := range connections {
		_ = conn.CloseWithError(code, reason)
	}
}

func readDoQMessage(reader io.Reader) ([]byte, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &protocolViolation{reason: "incomplete DNS message length"}
		}
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length < 12 || length > maxDNSMessageSize {
		return nil, &protocolViolation{reason: "invalid DNS message length"}
	}

	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &protocolViolation{reason: "incomplete DNS message"}
		}
		return nil, err
	}
	if message[0] != 0 || message[1] != 0 {
		return nil, &protocolViolation{reason: "DNS message ID must be zero"}
	}

	extra, err := io.ReadAll(io.LimitReader(reader, 1))
	if err != nil {
		return nil, err
	}
	if len(extra) != 0 {
		return nil, &protocolViolation{reason: "multiple DNS messages on one stream"}
	}
	return message, nil
}

func writeDoQMessage(writer io.Writer, message []byte) error {
	if len(message) < 12 || len(message) > maxDNSMessageSize {
		return fmt.Errorf("invalid DNS response length %d", len(message))
	}
	var lengthBytes [2]byte
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(len(message)))
	if err := writeAll(writer, lengthBytes[:]); err != nil {
		return err
	}
	return writeAll(writer, message)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func buildProxyV2Header(sourceAddr, destinationAddr net.Addr) ([]byte, error) {
	source, ok := sourceAddr.(*net.UDPAddr)
	if !ok || source == nil {
		return nil, fmt.Errorf("unsupported DoQ source address %T", sourceAddr)
	}
	destination, ok := destinationAddr.(*net.UDPAddr)
	if !ok || destination == nil {
		return nil, fmt.Errorf("unsupported DoQ destination address %T", destinationAddr)
	}

	alpnTLV := []byte{0x01, 0x00, 0x03, 'd', 'o', 'q'}
	sourceV4 := source.IP.To4()
	if sourceV4 != nil {
		destinationV4 := destination.IP.To4()
		if destinationV4 == nil {
			destinationV4 = net.IPv4zero.To4()
		}
		return makeProxyV2Header(0x12, sourceV4, destinationV4, source.Port, destination.Port, alpnTLV), nil
	}

	sourceV6 := source.IP.To16()
	if sourceV6 == nil {
		return nil, fmt.Errorf("invalid DoQ source address %q", source.IP)
	}
	destinationV6 := destination.IP.To16()
	if destinationV6 == nil || destination.IP.To4() != nil {
		destinationV6 = net.IPv6zero
	}
	return makeProxyV2Header(0x22, sourceV6, destinationV6, source.Port, destination.Port, alpnTLV), nil
}

func makeProxyV2Header(familyProtocol byte, sourceIP, destinationIP net.IP, sourcePort, destinationPort int, tlv []byte) []byte {
	addressLength := 12
	if familyProtocol == 0x22 {
		addressLength = 36
	}
	payloadLength := addressLength + len(tlv)
	header := make([]byte, 16+payloadLength)
	copy(header[:12], proxyV2Signature[:])
	header[12] = 0x21
	header[13] = familyProtocol
	binary.BigEndian.PutUint16(header[14:16], uint16(payloadLength))

	if familyProtocol == 0x12 {
		copy(header[16:20], sourceIP.To4())
		copy(header[20:24], destinationIP.To4())
		binary.BigEndian.PutUint16(header[24:26], uint16(sourcePort))
		binary.BigEndian.PutUint16(header[26:28], uint16(destinationPort))
	} else {
		copy(header[16:32], sourceIP.To16())
		copy(header[32:48], destinationIP.To16())
		binary.BigEndian.PutUint16(header[48:50], uint16(sourcePort))
		binary.BigEndian.PutUint16(header[50:52], uint16(destinationPort))
	}
	copy(header[16+addressLength:], tlv)
	return header
}

func isTimeout(err error) bool {
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func loadConfig(path string) (*configFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg configFile
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func makeTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	reloader, err := newCertificateReloader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		GetCertificate: reloader.GetCertificate,
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{doqALPN},
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

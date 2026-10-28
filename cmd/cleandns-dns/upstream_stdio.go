package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const maxDoQBridgeLineSize = 256 * 1024

type doqUpstreamRequest struct {
	ID         string `json:"id"`
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
	TimeoutMs  int    `json:"timeoutMs"`
	Packet     string `json:"packet"`
}

type doqUpstreamResponse struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Packet string `json:"packet,omitempty"`
	Error  string `json:"error,omitempty"`
}

type doqUpstreamPool struct {
	mu         sync.Mutex
	entries    map[string]*doqUpstreamEntry
	baseTLS    *tls.Config
	quicConfig *quic.Config
	closed     bool
}

type doqUpstreamEntry struct {
	mu   sync.Mutex
	conn *quic.Conn
}

func newDoQUpstreamPool(baseTLS *tls.Config) *doqUpstreamPool {
	if baseTLS == nil {
		baseTLS = &tls.Config{}
	}
	return &doqUpstreamPool{
		entries: make(map[string]*doqUpstreamEntry),
		baseTLS: baseTLS.Clone(),
		quicConfig: &quic.Config{
			HandshakeIdleTimeout:  5 * time.Second,
			MaxIdleTimeout:        30 * time.Second,
			KeepAlivePeriod:       15 * time.Second,
			MaxIncomingStreams:    -1,
			MaxIncomingUniStreams: -1,
		},
	}
}

func (p *doqUpstreamPool) Query(ctx context.Context, address, serverName string, packet []byte) ([]byte, error) {
	if len(packet) < 12 || len(packet) > maxDNSMessageSize {
		return nil, fmt.Errorf("invalid DNS query length %d", len(packet))
	}
	query := append([]byte(nil), packet...)
	originalID := [2]byte{query[0], query[1]}
	query[0], query[1] = 0, 0

	for attempt := 0; attempt < 2; attempt++ {
		entry, conn, err := p.connection(ctx, address, serverName)
		if err != nil {
			return nil, err
		}
		response, err := exchangeDoQ(ctx, conn, query)
		if err == nil {
			response[0], response[1] = originalID[0], originalID[1]
			return response, nil
		}
		p.evict(entry, conn)
		var violation *protocolViolation
		if errors.As(err, &violation) || ctx.Err() != nil || attempt == 1 {
			return nil, err
		}
	}
	return nil, errors.New("DoQ query failed")
}

func (p *doqUpstreamPool) connection(ctx context.Context, address, serverName string) (*doqUpstreamEntry, *quic.Conn, error) {
	key := address + "\x00" + serverName
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, nil, errors.New("DoQ upstream pool is closed")
	}
	entry := p.entries[key]
	if entry == nil {
		entry = &doqUpstreamEntry{}
		p.entries[key] = entry
	}
	p.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return entry, nil, errors.New("DoQ upstream pool is closed")
	}
	if entry.conn != nil && entry.conn.Context().Err() == nil {
		return entry, entry.conn, nil
	}
	entry.conn = nil

	tlsConfig := p.baseTLS.Clone()
	tlsConfig.ServerName = serverName
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{doqALPN}
	conn, err := quic.DialAddr(ctx, address, tlsConfig, p.quicConfig.Clone())
	if err != nil {
		return entry, nil, err
	}
	entry.conn = conn
	return entry, conn, nil
}

func (p *doqUpstreamPool) evict(entry *doqUpstreamEntry, conn *quic.Conn) {
	if entry == nil || conn == nil {
		return
	}
	entry.mu.Lock()
	if entry.conn == conn {
		entry.conn = nil
	}
	entry.mu.Unlock()
	_ = conn.CloseWithError(doqInternalError, "upstream connection reset")
}

func (p *doqUpstreamPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	entries := make([]*doqUpstreamEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.mu.Unlock()

	for _, entry := range entries {
		entry.mu.Lock()
		conn := entry.conn
		entry.conn = nil
		entry.mu.Unlock()
		if conn != nil {
			_ = conn.CloseWithError(doqNoError, "bridge shutdown")
		}
	}
}

func exchangeDoQ(ctx context.Context, conn *quic.Conn, packet []byte) ([]byte, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	if err = writeDoQMessage(stream, packet); err == nil {
		err = stream.Close()
	}
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(doqRequestCancelled))
		stream.CancelWrite(quic.StreamErrorCode(doqRequestCancelled))
		return nil, err
	}
	response, err := readDoQMessage(stream)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(doqRequestCancelled))
		return nil, err
	}
	return response, nil
}

func runDoQUpstreamStdio(ctx context.Context, input io.Reader, output io.Writer, pool *doqUpstreamPool) error {
	if pool == nil {
		pool = newDoQUpstreamPool(nil)
	}
	defer pool.Close()

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxDoQBridgeLineSize)
	encoder := json.NewEncoder(output)
	var workers sync.WaitGroup
	var outputMu sync.Mutex
	var writeErr error

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := handleDoQUpstreamLine(ctx, line, pool)
			outputMu.Lock()
			defer outputMu.Unlock()
			if writeErr == nil {
				writeErr = encoder.Encode(response)
			}
		}()
	}
	workers.Wait()
	if err := scanner.Err(); err != nil {
		return err
	}
	return writeErr
}

func handleDoQUpstreamLine(parent context.Context, line string, pool *doqUpstreamPool) doqUpstreamResponse {
	var request doqUpstreamRequest
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return doqUpstreamFailure(request.ID, "bad_request")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return doqUpstreamFailure(request.ID, "bad_request")
	}
	if !validBridgeID(request.ID) {
		return doqUpstreamFailure(request.ID, "bad_request_id")
	}
	address, serverName, err := validateDoQUpstreamTarget(request.Address, request.ServerName)
	if err != nil {
		return doqUpstreamFailure(request.ID, err.Error())
	}
	if request.TimeoutMs < 1 || request.TimeoutMs > 30000 {
		return doqUpstreamFailure(request.ID, "bad_timeout")
	}
	packet, err := base64.StdEncoding.Strict().DecodeString(request.Packet)
	if err != nil || len(packet) < 12 || len(packet) > maxDNSMessageSize {
		return doqUpstreamFailure(request.ID, "bad_dns_query")
	}

	ctx, cancel := context.WithTimeout(parent, time.Duration(request.TimeoutMs)*time.Millisecond)
	defer cancel()
	response, err := pool.Query(ctx, address, serverName, packet)
	if err != nil {
		return doqUpstreamFailure(request.ID, bridgeError(err, ctx))
	}
	return doqUpstreamResponse{
		ID:     request.ID,
		OK:     true,
		Packet: base64.StdEncoding.EncodeToString(response),
	}
}

func validateDoQUpstreamTarget(address, serverName string) (string, string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || net.ParseIP(host) == nil {
		return "", "", errors.New("bad_doq_address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", errors.New("bad_doq_address")
	}
	serverName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(serverName)), ".")
	if serverName == "" {
		serverName = host
	}
	if net.ParseIP(serverName) == nil && serverName != "localhost" && !validDNSHostname(serverName) {
		return "", "", errors.New("bad_doq_server_name")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), serverName, nil
}

func validDNSHostname(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func validBridgeID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, char := range id {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && !strings.ContainsRune("._:-", char) {
			return false
		}
	}
	return true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func doqUpstreamFailure(id, message string) doqUpstreamResponse {
	return doqUpstreamResponse{ID: id, OK: false, Error: message}
}

func bridgeError(err error, ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || isTimeout(err) {
		return "timeout"
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	if message == "" {
		return "doq_query_failed"
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

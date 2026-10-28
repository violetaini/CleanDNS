package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

type testDoQUpstream struct {
	listener    *quic.Listener
	connections atomic.Int32
	queries     chan []byte
}

func TestDoQUpstreamPoolRoundTripAndConnectionReuse(t *testing.T) {
	endpoint := startTestDoQUpstream(t)
	pool := newDoQUpstreamPool(&tls.Config{InsecureSkipVerify: true})
	t.Cleanup(pool.Close)

	for _, id := range []uint16{0x1234, 0x5678} {
		query := testDNSQueryWithID(id)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		response, err := pool.Query(ctx, endpoint.listener.Addr().String(), "dns.test", query)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if got := uint16(response[0])<<8 | uint16(response[1]); got != id {
			t.Fatalf("response ID = %#x, want %#x", got, id)
		}
		if response[2]&0x80 == 0 {
			t.Fatalf("response does not have QR bit: %x", response[:4])
		}
		select {
		case received := <-endpoint.queries:
			if received[0] != 0 || received[1] != 0 {
				t.Fatalf("wire query ID = %x, want zero", received[:2])
			}
		case <-time.After(time.Second):
			t.Fatal("DoQ upstream did not receive query")
		}
	}
	if got := endpoint.connections.Load(); got != 1 {
		t.Fatalf("accepted connections = %d, want one reused connection", got)
	}
}

func TestDoQUpstreamPoolConcurrentStreams(t *testing.T) {
	endpoint := startTestDoQUpstream(t)
	pool := newDoQUpstreamPool(&tls.Config{InsecureSkipVerify: true})
	t.Cleanup(pool.Close)

	const queryCount = 64
	var workers sync.WaitGroup
	errorsCh := make(chan error, queryCount)
	for i := 0; i < queryCount; i++ {
		workers.Add(1)
		go func(id uint16) {
			defer workers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			response, err := pool.Query(ctx, endpoint.listener.Addr().String(), "dns.test", testDNSQueryWithID(id))
			if err == nil && (uint16(response[0])<<8|uint16(response[1])) != id {
				err = fmt.Errorf("response ID mismatch for %#x", id)
			}
			if err != nil {
				errorsCh <- err
			}
		}(uint16(i + 1))
	}
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	if got := endpoint.connections.Load(); got != 1 {
		t.Fatalf("accepted connections = %d, want one shared connection", got)
	}
}

func TestDoQUpstreamStdioProtocol(t *testing.T) {
	endpoint := startTestDoQUpstream(t)
	pool := newDoQUpstreamPool(&tls.Config{InsecureSkipVerify: true})
	query := testDNSQueryWithID(0x4242)
	requests := []doqUpstreamRequest{
		{
			ID:         "request-1",
			Address:    endpoint.listener.Addr().String(),
			ServerName: "dns.test",
			TimeoutMs:  2000,
			Packet:     base64.StdEncoding.EncodeToString(query),
		},
		{
			ID:         "request-2",
			Address:    "dns.test:853",
			ServerName: "dns.test",
			TimeoutMs:  2000,
			Packet:     base64.StdEncoding.EncodeToString(query),
		},
	}

	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	for _, request := range requests {
		if err := encoder.Encode(request); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := runDoQUpstreamStdio(context.Background(), &input, &output, pool); err != nil {
		t.Fatal(err)
	}

	responses := map[string]doqUpstreamResponse{}
	scanner := bufio.NewScanner(&output)
	for scanner.Scan() {
		var response doqUpstreamResponse
		if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		responses[response.ID] = response
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if response := responses["request-1"]; !response.OK || response.Error != "" {
		t.Fatalf("successful response = %+v", response)
	} else if packet, err := base64.StdEncoding.DecodeString(response.Packet); err != nil {
		t.Fatalf("decode response packet: %v", err)
	} else if len(packet) < 12 || packet[0] != query[0] || packet[1] != query[1] || packet[2]&0x80 == 0 {
		t.Fatalf("invalid response packet: %x", packet)
	}
	if response := responses["request-2"]; response.OK || response.Error != "bad_doq_address" {
		t.Fatalf("invalid-target response = %+v", response)
	}
}

func TestDoQUpstreamStdioRejectsMalformedRequests(t *testing.T) {
	pool := newDoQUpstreamPool(nil)
	t.Cleanup(pool.Close)
	tests := map[string]string{
		"unknown field": `{"id":"a","address":"127.0.0.1:853","serverName":"dns.test","timeoutMs":100,"packet":"AA==","extra":true}`,
		"bad id":        `{"id":"bad id","address":"127.0.0.1:853","serverName":"dns.test","timeoutMs":100,"packet":"AA=="}`,
		"bad packet":    `{"id":"a","address":"127.0.0.1:853","serverName":"dns.test","timeoutMs":100,"packet":"not base64"}`,
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			response := handleDoQUpstreamLine(context.Background(), line, pool)
			if response.OK || response.Error == "" {
				t.Fatalf("response = %+v, want structured failure", response)
			}
		})
	}
}

func startTestDoQUpstream(t *testing.T) *testDoQUpstream {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", testTLSConfig(t), &quic.Config{
		HandshakeIdleTimeout:  time.Second,
		MaxIdleTimeout:        10 * time.Second,
		MaxIncomingStreams:    256,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &testDoQUpstream{
		listener: listener,
		queries:  make(chan []byte, 256),
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				return
			}
			endpoint.connections.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.CloseWithError(doqNoError, "")
				for {
					stream, streamErr := conn.AcceptStream(ctx)
					if streamErr != nil {
						return
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						query, queryErr := readDoQMessage(stream)
						if queryErr != nil {
							stream.CancelWrite(quic.StreamErrorCode(doqProtocolError))
							return
						}
						endpoint.queries <- append([]byte(nil), query...)
						response := append([]byte(nil), query...)
						response[2] |= 0x80
						if writeDoQMessage(stream, response) == nil {
							_ = stream.Close()
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		done := make(chan struct{})
		go func() {
			workers.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("test DoQ upstream did not stop")
		}
	})
	return endpoint
}

func testDNSQueryWithID(id uint16) []byte {
	query := append([]byte(nil), testDNSQuery()...)
	query[0], query[1] = byte(id>>8), byte(id)
	return query
}

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
)

type certificateFileState struct {
	certSize    int64
	certModTime int64
	keySize     int64
	keyModTime  int64
}

type certificateReloader struct {
	certFile string
	keyFile  string

	mu          sync.Mutex
	certificate *tls.Certificate
	state       certificateFileState
	failedState certificateFileState
}

func newCertificateReloader(certFile, keyFile string) (*certificateReloader, error) {
	certificate, state, err := loadStableKeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &certificateReloader{
		certFile:    certFile,
		keyFile:     keyFile,
		certificate: certificate,
		state:       state,
	}, nil
}

func (r *certificateReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := inspectCertificateFiles(r.certFile, r.keyFile)
	if err != nil {
		if r.certificate != nil {
			return r.certificate, nil
		}
		return nil, err
	}
	if state == r.state || state == r.failedState {
		return r.certificate, nil
	}

	certificate, loadedState, err := loadStableKeyPair(r.certFile, r.keyFile)
	if err != nil {
		r.failedState = state
		log.Printf("keep current DoQ certificate after reload failure: %v", err)
		return r.certificate, nil
	}
	r.certificate = certificate
	r.state = loadedState
	r.failedState = certificateFileState{}
	log.Printf("reloaded DoQ TLS certificate from %s", r.certFile)
	return r.certificate, nil
}

func loadStableKeyPair(certFile, keyFile string) (*tls.Certificate, certificateFileState, error) {
	for attempt := 0; attempt < 3; attempt++ {
		before, err := inspectCertificateFiles(certFile, keyFile)
		if err != nil {
			return nil, certificateFileState{}, err
		}
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, certificateFileState{}, err
		}
		after, err := inspectCertificateFiles(certFile, keyFile)
		if err != nil {
			return nil, certificateFileState{}, err
		}
		if before == after {
			return &certificate, after, nil
		}
	}
	return nil, certificateFileState{}, errors.New("TLS certificate files changed while loading")
}

func inspectCertificateFiles(certFile, keyFile string) (certificateFileState, error) {
	certInfo, err := os.Stat(certFile)
	if err != nil {
		return certificateFileState{}, fmt.Errorf("inspect TLS certificate: %w", err)
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return certificateFileState{}, fmt.Errorf("inspect TLS private key: %w", err)
	}
	if !certInfo.Mode().IsRegular() || !keyInfo.Mode().IsRegular() {
		return certificateFileState{}, errors.New("TLS certificate and private key must be regular files")
	}
	return certificateFileState{
		certSize:    certInfo.Size(),
		certModTime: certInfo.ModTime().UnixNano(),
		keySize:     keyInfo.Size(),
		keyModTime:  keyInfo.ModTime().UnixNano(),
	}, nil
}

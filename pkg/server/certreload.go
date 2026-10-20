package server

import (
	"crypto/tls"
	"log/slog"
	"os"
	"sync"
	"time"
)

// certReloadInterval is how often a handshake re-checks the certificate files,
// matching the 5 minute reload of the Rust server.
const certReloadInterval = 5 * time.Minute

// certReloader serves a TLS certificate and picks up a renewed one (certbot,
// cert-manager) without a restart. The files are stat'ed on a handshake at most
// once per interval; a pair that fails to load keeps the previous certificate.
type certReloader struct {
	certFile, keyFile string
	interval          time.Duration

	mu      sync.Mutex
	cert    *tls.Certificate
	checked time.Time
	certSig fileSig
	keySig  fileSig
}

type fileSig struct {
	mod  time.Time
	size int64
}

func sigOf(path string) (fileSig, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileSig{}, err
	}
	return fileSig{mod: fi.ModTime(), size: fi.Size()}, nil
}

// newCertReloader loads the pair once; a failure here is a startup error.
func newCertReloader(certFile, keyFile string, interval time.Duration) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, interval: interval}
	if err := r.load(); err != nil {
		return nil, err
	}
	r.checked = time.Now()
	return r, nil
}

func (r *certReloader) load() error {
	// Signatures first: a file replaced between stat and read is simply
	// picked up again on the next check.
	cs, err := sigOf(r.certFile)
	if err != nil {
		return err
	}
	ks, err := sigOf(r.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.certSig, r.keySig = &cert, cs, ks
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) >= r.interval {
		r.checked = time.Now()
		cs, cerr := sigOf(r.certFile)
		ks, kerr := sigOf(r.keyFile)
		if cerr == nil && kerr == nil && (cs != r.certSig || ks != r.keySig) {
			if err := r.load(); err != nil {
				// A renewal writes the two files one after the other, so a
				// mismatched pair is expected for a moment. Retry next check.
				slog.Warn("TLS certificate reload failed; keeping the previous certificate", "err", err)
				// Look again soon, not after a full interval.
				r.checked = time.Now().Add(-r.interval + min(r.interval, 10*time.Second))
			} else {
				slog.Info("TLS certificate reloaded", "cert", r.certFile)
			}
		}
	}
	return r.cert, nil
}

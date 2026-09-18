// Package certcache provides on-demand TLS leaf certificate generation
// signed by a configured CA, with an LRU cache keyed by domain name.
package certcache

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Cache generates and caches per-domain TLS leaf certificates signed by a CA.
type Cache struct {
	caCert     *x509.Certificate
	caKey      crypto.Signer
	leafExpiry time.Duration

	mu    sync.Mutex // protects against concurrent generate for the same domain
	cache *expirable.LRU[string, *tls.Certificate]
}

// New creates a Cache that loads the CA certificate and key from the given paths.
func New(caCertPath, caKeyPath string, maxSize int, leafExpiry time.Duration) (*Cache, error) {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, err
	}

	return NewFromCA(caCert, caKey, maxSize, leafExpiry)
}

// NewFromCA creates a Cache directly from an already-loaded CA cert and key.
// Returns an error if the certificate is not a valid CA (missing IsCA or
// KeyUsageCertSign).
func NewFromCA(caCert *x509.Certificate, caKey crypto.Signer, maxSize int, leafExpiry time.Duration) (*Cache, error) {
	if !caCert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA (BasicConstraints.IsCA is false)")
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("CA certificate missing KeyUsageCertSign")
	}

	cache := expirable.NewLRU[string, *tls.Certificate](maxSize, nil, leafExpiry)

	return &Cache{
		caCert:     caCert,
		caKey:      caKey,
		leafExpiry: leafExpiry,
		cache:      cache,
	}, nil
}

// GetOrCreate returns a cached TLS certificate for the domain, or generates
// and caches a new one. Safe for concurrent use.
func (c *Cache) GetOrCreate(domain string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cert, ok := c.cache.Get(domain); ok {
		// The LRU expiry uses Go's monotonic clock, which does not advance while
		// the host is suspended. Certificate validity uses wall time, so reject a
		// cached leaf that has expired even when its LRU entry is still alive.
		if cert.Leaf != nil && time.Now().Before(cert.Leaf.NotAfter) {
			return cert, nil
		}
		c.cache.Remove(domain)
	}

	cert, err := c.generate(domain)
	if err != nil {
		return nil, fmt.Errorf("generating cert for %s: %w", domain, err)
	}

	c.cache.Add(domain, cert)
	return cert, nil
}

// Len returns the number of cached certificates.
func (c *Cache) Len() int {
	return c.cache.Len()
}

func (c *Cache) generate(domain string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(c.leafExpiry),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.caCert, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated certificate: %w", err)
	}

	return &tls.Certificate{
		// Include the signing CA so clients can build the full chain when the
		// configured CA is an intermediate and clients trust its parent root.
		Certificate: [][]byte{certDER, c.caCert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA cert: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in CA cert")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in CA key")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS1 (RSA) format as fallback
		parsed, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Try EC private key format as final fallback
			parsed, err = x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing CA key (tried PKCS8, PKCS1, and EC formats): %w", err)
			}
		}
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("CA key does not implement crypto.Signer")
	}

	return caCert, signer, nil
}

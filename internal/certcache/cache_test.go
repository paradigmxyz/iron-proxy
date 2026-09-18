package certcache

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func newTestCache(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer, maxSize int) *Cache {
	t.Helper()
	c, err := NewFromCA(caCert, caKey, maxSize, 72*time.Hour)
	require.NoError(t, err)
	return c
}

func TestNewFromCA_RejectsNonCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Leaf cert — not a CA
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Not A CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = NewFromCA(cert, key, 10, 72*time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a CA")
}

func TestNewFromCA_RejectsMissingCertSign(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bad CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature, // missing CertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = NewFromCA(cert, key, 10, 72*time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "KeyUsageCertSign")
}

func writeTestCA(t *testing.T, dir string, cert *x509.Certificate, certDER []byte, keyPEM []byte) (string, string) {
	t.Helper()

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(certPath, certPEMBytes, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath
}

func TestLoadCA_PKCS8ECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPath, keyPath := writeTestCA(t, t.TempDir(), cert, certDER, keyPEM)

	caCert, signer, err := loadCA(certPath, keyPath)
	require.NoError(t, err)
	require.Equal(t, "Test CA", caCert.Subject.CommonName)
	require.NotNil(t, signer)
}

func TestLoadCA_PKCS8RSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test RSA CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPath, keyPath := writeTestCA(t, t.TempDir(), cert, certDER, keyPEM)

	caCert, signer, err := loadCA(certPath, keyPath)
	require.NoError(t, err)
	require.Equal(t, "Test RSA CA", caCert.Subject.CommonName)
	require.NotNil(t, signer)
}

func TestLoadCA_PKCS1RSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test PKCS1 CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPath, keyPath := writeTestCA(t, t.TempDir(), cert, certDER, keyPEM)

	caCert, signer, err := loadCA(certPath, keyPath)
	require.NoError(t, err)
	require.Equal(t, "Test PKCS1 CA", caCert.Subject.CommonName)
	require.NotNil(t, signer)
}

func TestLoadCA_ECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test EC CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPath, keyPath := writeTestCA(t, t.TempDir(), cert, certDER, keyPEM)

	caCert, signer, err := loadCA(certPath, keyPath)
	require.NoError(t, err)
	require.Equal(t, "Test EC CA", caCert.Subject.CommonName)
	require.NotNil(t, signer)
}

func TestGetOrCreate_GeneratesCert(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 10)

	cert, err := c.GetOrCreate("example.com")
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, cert.Leaf)
	require.Equal(t, "example.com", cert.Leaf.Subject.CommonName)
	require.Contains(t, cert.Leaf.DNSNames, "example.com")
}

func TestGetOrCreate_VerifiesAgainstCA(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 10)

	cert, err := c.GetOrCreate("example.com")
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   pool,
	})
	require.NoError(t, err)
}

func TestGetOrCreate_ServesSigningCAForIntermediateChain(t *testing.T) {
	rootCert, rootKey := generateTestCA(t)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		intermediateTemplate,
		rootCert,
		&intermediateKey.PublicKey,
		rootKey,
	)
	require.NoError(t, err)
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	c := newTestCache(t, intermediateCert, intermediateKey, 10)
	cert, err := c.GetOrCreate("example.com")
	require.NoError(t, err)
	require.Len(t, cert.Certificate, 2)

	servedIntermediate, err := x509.ParseCertificate(cert.Certificate[1])
	require.NoError(t, err)
	require.Equal(t, intermediateCert.Raw, servedIntermediate.Raw)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(servedIntermediate)

	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:       "example.com",
		Roots:         roots,
		Intermediates: intermediates,
	})
	require.NoError(t, err)
}

func TestGetOrCreate_CacheHit(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 10)

	cert1, err := c.GetOrCreate("example.com")
	require.NoError(t, err)

	cert2, err := c.GetOrCreate("example.com")
	require.NoError(t, err)

	// Same pointer — served from cache
	require.Same(t, cert1, cert2)
	require.Equal(t, 1, c.Len())
}

func TestGetOrCreate_ExpiredLeaf(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 10)

	cert1, err := c.GetOrCreate("example.com")
	require.NoError(t, err)
	cert1.Leaf.NotAfter = time.Now().Add(-time.Minute)

	cert2, err := c.GetOrCreate("example.com")
	require.NoError(t, err)

	require.NotSame(t, cert1, cert2)
	require.True(t, cert2.Leaf.NotAfter.After(time.Now()))
	require.Equal(t, 1, c.Len())
}

func TestGetOrCreate_DifferentDomains(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 10)

	cert1, err := c.GetOrCreate("a.example.com")
	require.NoError(t, err)

	cert2, err := c.GetOrCreate("b.example.com")
	require.NoError(t, err)

	require.NotSame(t, cert1, cert2)
	require.Equal(t, 2, c.Len())
}

func TestGetOrCreate_Eviction(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 3)

	// Fill the cache
	for _, domain := range []string{"a.com", "b.com", "c.com"} {
		_, err := c.GetOrCreate(domain)
		require.NoError(t, err)
	}
	require.Equal(t, 3, c.Len())

	// Adding a 4th evicts the oldest (a.com)
	_, err := c.GetOrCreate("d.com")
	require.NoError(t, err)
	require.Equal(t, 3, c.Len())

	// a.com should be evicted — next call generates a new cert
	certA, err := c.GetOrCreate("a.com")
	require.NoError(t, err)
	require.NotNil(t, certA)
	require.Equal(t, "a.com", certA.Leaf.Subject.CommonName)
}

func TestGetOrCreate_LRUTouchPreventsEviction(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 3)

	// Fill: a, b, c
	_, err := c.GetOrCreate("a.com")
	require.NoError(t, err)
	_, err = c.GetOrCreate("b.com")
	require.NoError(t, err)
	_, err = c.GetOrCreate("c.com")
	require.NoError(t, err)

	// Touch a.com — now b.com is the oldest
	certA1, err := c.GetOrCreate("a.com")
	require.NoError(t, err)

	// Add d.com — should evict b.com (oldest), not a.com
	_, err = c.GetOrCreate("d.com")
	require.NoError(t, err)

	// a.com should still be cached (same pointer)
	certA2, err := c.GetOrCreate("a.com")
	require.NoError(t, err)
	require.Same(t, certA1, certA2)
}

func TestGetOrCreate_Concurrent(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	c := newTestCache(t, caCert, caKey, 100)

	var wg sync.WaitGroup
	domains := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			domain := domains[i%len(domains)]
			cert, err := c.GetOrCreate(domain)
			require.NoError(t, err)
			require.NotNil(t, cert)
		}()
	}

	wg.Wait()
	require.Equal(t, 5, c.Len())
}

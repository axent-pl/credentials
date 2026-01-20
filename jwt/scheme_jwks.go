package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
	jwtx "github.com/golang-jwt/jwt/v5"
)

type JWKSJWTScheme struct {
	JWKSURL         url.URL
	Client          *http.Client  // optional; defaults to http.DefaultClient
	RefreshInterval time.Duration // RefreshInterval <= 0 disables cache refresh

	mu        sync.RWMutex
	cached    *DefaultJWTScheme
	lastErr   error
	etag      string
	lastMod   string
	lastFetch time.Time
	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
	started   bool
}

var _ JWTSchemer = (*JWKSJWTScheme)(nil)
var _ common.Scheme = (*JWKSJWTScheme)(nil)

func (p *JWKSJWTScheme) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		if p.Client == nil {
			p.Client = http.DefaultClient
		}
		p.stopCh = make(chan struct{})
		p.started = true

		// Warm the cache.
		go func() {
			_ = p.refresh(ctx)
		}()

		if p.RefreshInterval <= 0 {
			// Disable cache refresh
			return
		}

		t := time.NewTicker(p.RefreshInterval)
		go func() {
			defer t.Stop()
			for {
				select {
				case <-t.C:
					_ = p.refresh(context.Background())
				case <-p.stopCh:
					return
				}
			}
		}()
	})
}

func (p *JWKSJWTScheme) Close() {
	p.stopOnce.Do(func() {
		if p.started && p.stopCh != nil {
			close(p.stopCh)
		}
	})
}

// --- internal types/helpers ---

// jwksResponse represents a JWKS document extended with optional fields.
// Standard JWKS uses only "keys". We also accept "valid_methods" and "issuer".
type jwksResponse struct {
	Keys         []jwkKey `json:"keys"`
	ValidMethods []string `json:"valid_methods,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
}

type jwkKey struct {
	Use       string   `json:"use,omitempty"`
	Kty       string   `json:"kty,omitempty"`
	Kid       string   `json:"kid,omitempty"`
	Crv       string   `json:"crv,omitempty"`
	Alg       string   `json:"alg,omitempty"`
	K         string   `json:"k,omitempty"`
	X         string   `json:"x,omitempty"`
	Y         string   `json:"y,omitempty"`
	N         string   `json:"n,omitempty"`
	E         string   `json:"e,omitempty"`
	X5c       []string `json:"x5c,omitempty"`
	X5u       *url.URL `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

func b64uToBigInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("empty base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func JwkToPublicKey(k jwkKey) (crypto.PublicKey, error) {
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		n, err := b64uToBigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("rsa n: %w", err)
		}
		eBig, err := b64uToBigInt(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		if !eBig.IsInt64() || eBig.Int64() > int64(^uint32(0)>>1) {
			return nil, errors.New("rsa exponent too large")
		}
		e := int(eBig.Int64())
		return &rsa.PublicKey{N: n, E: e}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %q", k.Crv)
		}
		x, err := b64uToBigInt(k.X)
		if err != nil {
			return nil, fmt.Errorf("ec x: %w", err)
		}
		y, err := b64uToBigInt(k.Y)
		if err != nil {
			return nil, fmt.Errorf("ec y: %w", err)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty: %q", k.Kty)
	}
}

func (p *JWKSJWTScheme) ensureCache() {
	p.mu.RLock()
	cached := p.cached
	p.mu.RUnlock()
	if cached != nil {
		return
	}
	_ = p.refresh(context.Background())
}

func (p *JWKSJWTScheme) cachedScheme() *DefaultJWTScheme {
	p.ensureCache()
	p.mu.RLock()
	cached := p.cached
	p.mu.RUnlock()
	return cached
}

func (p *JWKSJWTScheme) Kind() common.Kind { return common.JWT }

func (p *JWKSJWTScheme) GetSubject() common.SubjectID {
	cached := p.cachedScheme()
	if cached == nil {
		return ""
	}
	return cached.GetSubject()
}

func (p *JWKSJWTScheme) GetMustMatchKid() bool {
	cached := p.cachedScheme()
	if cached == nil {
		return false
	}
	return cached.GetMustMatchKid()
}

func (p *JWKSJWTScheme) GetKeys() []sig.SignatureVerificationKey {
	cached := p.cachedScheme()
	if cached == nil || len(cached.Keys) == 0 {
		return nil
	}
	keys := make([]sig.SignatureVerificationKey, len(cached.Keys))
	copy(keys, cached.Keys)
	return keys
}

func (p *JWKSJWTScheme) GetIssuer() string {
	cached := p.cachedScheme()
	if cached == nil {
		return ""
	}
	return cached.GetIssuer()
}

func (p *JWKSJWTScheme) GetAudience() string {
	cached := p.cachedScheme()
	if cached == nil {
		return ""
	}
	return cached.GetAudience()
}

func (p *JWKSJWTScheme) GetLeeway() time.Duration {
	cached := p.cachedScheme()
	if cached == nil {
		return 0
	}
	return cached.GetLeeway()
}

func (p *JWKSJWTScheme) GetReplay() common.ReplayChecker {
	cached := p.cachedScheme()
	if cached == nil {
		return nil
	}
	return cached.GetReplay()
}

func (p *JWKSJWTScheme) ParsePrincipal(claims *jwtx.RegisteredClaims) (common.Principal, error) {
	cached := p.cachedScheme()
	if cached != nil {
		return cached.ParsePrincipal(claims)
	}
	return DefaultJWTScheme{}.ParsePrincipal(claims)
}

// refresh fetches JWKS with conditional headers and updates the cache if changed.
func (p *JWKSJWTScheme) refresh(ctx context.Context) error {
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.JWKSURL.String(), nil)
	if err != nil {
		return fmt.Errorf("jwks request build failed: %w", err)
	}

	// Conditional GETs to avoid unnecessary downloads and to detect changes.
	p.mu.RLock()
	if p.etag != "" {
		req.Header.Set("If-None-Match", p.etag)
	}
	if p.lastMod != "" {
		req.Header.Set("If-Modified-Since", p.lastMod)
	}
	p.mu.RUnlock()

	resp, err := client.Do(req)
	if err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			p.mu.Lock()
			p.lastErr = fmt.Errorf("jwks fetch failed: %w", err)
			p.mu.Unlock()
			return p.lastErr
		}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logx.L().Error("could not close http.Response.Body")
		}
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// Nothing changed; keep current cache.
		p.mu.Lock()
		p.lastFetch = time.Now()
		p.lastErr = nil
		p.mu.Unlock()
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("jwks fetch failed: unexpected status %s", resp.Status)
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		return err
	}

	var doc jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		err = fmt.Errorf("jwks decode failed: %w", err)
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		return err
	}
	if len(doc.Keys) == 0 {
		err := errors.New("jwks contains no keys")
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		return err
	}

	keys := make([]sig.SignatureVerificationKey, 0, len(doc.Keys))
	allHaveKID := true
	for _, jk := range doc.Keys {
		pub, err := JwkToPublicKey(jk)
		if err != nil {
			err = fmt.Errorf("could not extract public key: %w", err)
			p.mu.Lock()
			p.lastErr = err
			p.mu.Unlock()
			return err
		}
		if jk.Kid == "" {
			allHaveKID = false
		}
		alg, _ := sig.FromOAuth(jk.Alg)

		keys = append(keys, sig.SignatureVerificationKey{
			Kid: jk.Kid,
			Key: pub,
			Alg: alg,
		})
	}

	if len(keys) == 0 {
		err := errors.New("no usable keys in jwks")
		p.mu.Lock()
		p.lastErr = err
		p.mu.Unlock()
		return err
	}

	scheme := DefaultJWTScheme{
		MustMatchKid: allHaveKID && len(keys) > 1, // require kid only if all keys provide it and there are multiple keys
		Keys:         keys,
	}

	// Update cache atomically.
	etag := resp.Header.Get("ETag")
	lastMod := resp.Header.Get("Last-Modified")

	p.mu.Lock()
	p.cached = &scheme
	p.lastErr = nil
	p.lastFetch = time.Now()
	if etag != "" {
		p.etag = etag
	}
	if lastMod != "" {
		p.lastMod = lastMod
	}
	p.mu.Unlock()

	return nil
}

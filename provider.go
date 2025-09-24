package auth

import "context"

type ValidationSchemeProvider interface {
	ValidationSchemes(ctx context.Context, in Credentials) ([]Scheme, error)
}

type ValidationSchemeProviderSet struct {
	Providers []ValidationSchemeProvider
}

func (s *ValidationSchemeProviderSet) ValidationSchemes(ctx context.Context, in Credentials) ([]Scheme, error) {
	var lastErr error
	var schemes []Scheme = make([]Scheme, 0)
	for _, p := range s.Providers {
		providerSchemes, err := p.ValidationSchemes(ctx, in)
		if err == nil {
			schemes = append(schemes, providerSchemes...)
		} else {
			lastErr = err
		}
	}
	if len(schemes) == 0 {
		return schemes, lastErr
	}
	return schemes, nil
}

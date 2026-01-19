package credentials

import (
	"context"

	"github.com/axent-pl/credentials/common"
)

type ValidationSchemeProvider interface {
	ValidationSchemes(ctx context.Context, in common.Credentials) ([]common.Scheme, error)
}

type ValidationSchemeProviderSet struct {
	Providers []ValidationSchemeProvider
}

func (s *ValidationSchemeProviderSet) ValidationSchemes(ctx context.Context, in common.Credentials) ([]common.Scheme, error) {
	var lastErr error
	schemes := make([]common.Scheme, 0)
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

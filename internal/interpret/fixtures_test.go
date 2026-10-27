package interpret

import (
	"github.com/helpnet/helpnet/internal/config"
	"github.com/helpnet/helpnet/internal/fixtures"
)

var th = config.DefaultThresholds()

var (
	ping     = fixtures.Ping
	repeat   = fixtures.Repeat
	tcp      = fixtures.TCP
	resolver = fixtures.Resolver
	okState  = fixtures.OK
	healthy  = fixtures.Healthy
	hop      = fixtures.Hop
)

func find(fs []Finding, rule string) *Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

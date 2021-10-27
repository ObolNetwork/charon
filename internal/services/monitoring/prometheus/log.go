package prometheus

import (
	zerologger "github.com/rs/zerolog/log"
)

var log = zerologger.With().Str("prefix", "prometheus").Logger()

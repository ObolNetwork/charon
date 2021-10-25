package runtime

import (
	zerologger "github.com/rs/zerolog/log"
)

var log = zerologger.With().Str("prefix", "runtime").Logger()

package cmd

import (
	zerologger "github.com/rs/zerolog/log"
)

var log = zerologger.With().Str("prefix", "cmd").Logger()

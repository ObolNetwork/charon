/*
Copyright © 2021 Oisín Kyne <oisin@obol.tech>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package logging

import (
	"strings"

	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// stringtoLevel converts a string to a log level.
// It returns the user-supplied level by default.
func StringToLevel(input string) zerolog.Level {
	switch strings.ToLower(input) {
	case "none":
		return zerolog.Disabled
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "info", "information":
		return zerolog.InfoLevel
	case "err", "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	default:
		return zerologger.Logger.GetLevel()
	}
}

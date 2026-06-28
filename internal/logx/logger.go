package logx

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Log is the global logger instance for the application.
var Log zerolog.Logger

func init() {
	// Initialize with a default standard logger outputting to stderr
	InitLogger(false, false, false, false)
}

// InitLogger configures the global logger level, output format, color support, and silence rules.
func InitLogger(verbose, silent, jsonFormat, noColor bool) {
	var output io.Writer = os.Stderr

	if silent {
		output = io.Discard
	} else if !jsonFormat {
		output = zerolog.ConsoleWriter{
			Out:        os.Stderr,
			NoColor:    noColor,
			TimeFormat: time.RFC3339,
		}
	}

	level := zerolog.InfoLevel
	if verbose {
		level = zerolog.DebugLevel
	}
	if silent {
		level = zerolog.Disabled
	}

	zerolog.SetGlobalLevel(level)
	Log = zerolog.New(output).With().Timestamp().Logger()
}

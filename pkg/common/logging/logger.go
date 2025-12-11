package logging

import (
	"log"
	"os"
)

// New returns a standard library logger with sane defaults.
func New(prefix string) *log.Logger {
	return log.New(os.Stdout, prefix+" ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
}

// SetVerbose toggles log flags for verbose output.
func SetVerbose(logger *log.Logger, verbose bool) {
	if logger == nil {
		return
	}
	if verbose {
		logger.SetFlags(log.LstdFlags | log.LUTC | log.Lmsgprefix | log.Lshortfile)
	} else {
		logger.SetFlags(log.LstdFlags | log.LUTC | log.Lmsgprefix)
	}
}

package logger

import (
	"io"
	"log"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	logFile *os.File
	// Logger is the central logger used across the application.
	Logger = logrus.New()
)

// Init configures the logger with the given output path and level.
// If path is empty, logs are written only to stdout.
func Init(path, level string) error {
	var writers []io.Writer
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		logFile = f
		writers = append(writers, f)
	}
	writers = append(writers, os.Stdout)
	mw := io.MultiWriter(writers...)

	Logger.SetOutput(mw)
	Logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	if lvl, err := logrus.ParseLevel(level); err == nil {
		Logger.SetLevel(lvl)
	} else {
		Logger.SetLevel(logrus.InfoLevel)
	}

	// Redirect standard library logs to logrus
	log.SetOutput(Logger.Writer())
	return nil
}

// Close closes the log file if it was opened.
func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

package logging

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
)

var Logger *logrus.Logger

func Setup(directory string, filename string, logLevel string, stdout bool) {
    // Create directory path if doesn't exist
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		err = os.MkdirAll(directory, 0750)
		if err != nil {
			panic(fmt.Sprintf("Unable to to write to create [%s] directory for logging", directory))
		}
	}

	var level logrus.Level
	level = LogLevel(logLevel)
	logger := &logrus.Logger{
		Level: level,
		Formatter: &logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		},
	}
	// Output calling method on message
	logger.SetReportCaller(true)

	file, err := os.OpenFile(fmt.Sprintf("%s/%s", directory, filename),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		if stdout {
			// Send to log file and standard out
			mw := io.MultiWriter(os.Stdout, file)
			logger.SetOutput(mw)
		} else {
			logger.SetOutput(file)
		}
	} else {
		panic(fmt.Sprintf("Failed to log to %s/%s, can not continue", directory, filename))
	}

	Logger = logger

	Logger.Info("Logger Initialized")
}

func LogLevel(lvl string) logrus.Level {
	switch lvl {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	default:
		panic("Log level not supported, verify settings for supported log level: [debug, info, error, fatal]")
	}
}
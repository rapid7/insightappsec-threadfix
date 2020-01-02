package metrics

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
)

var Metrics *logrus.Logger

func Setup(directory string, filename string, pretty bool) {
	logger := &logrus.Logger{
		Level: logrus.InfoLevel,
		Formatter: &logrus.JSONFormatter{
			DisableTimestamp: true,
			PrettyPrint: pretty,
		},
	}

	file, err := os.OpenFile(fmt.Sprintf("%s/%s", directory, filename),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logger.SetOutput(file)
	} else {
		logger.WithError(err).Fatalf("Failed to open metrics file %s, can not continue", file.Name())
	}

	Metrics = logger
}
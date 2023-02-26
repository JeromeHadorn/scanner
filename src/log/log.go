package log

import (
	"log"
	"os"
)
var (
	InfoLogger    *log.Logger
	WarningLogger *log.Logger
	ErrorLogger   *log.Logger
	ResultLogger   *log.Logger
)

func SetupLogger(logPath string, outputPath string) error {
	// Set up Log
	logFile := os.Stdout
	if logPath != "" {
		var err error
		logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Set up Output
	outputFile := os.Stdout
	if outputPath != "" {
		var err error
		outputFile, err = os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
	}

    InfoLogger = log.New(logFile, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
    WarningLogger = log.New(logFile, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
    ErrorLogger = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	ResultLogger = log.New(outputFile, "RESULT: ", log.Ldate|log.Ltime|log.Lshortfile)

	return nil
}
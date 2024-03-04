package debuglog

import (
	"log"
	"os"
)

type DebugLogger struct {
	Verbose bool
	*log.Logger
}

var Logger *DebugLogger

func (l *DebugLogger) Set() {
	l.Verbose = true
}

func NewDebugLogger(verbose bool) *DebugLogger {
	return &DebugLogger{
		Verbose: verbose,
		Logger:  log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (l *DebugLogger) Debug(v ...interface{}) {
	if l.Verbose {
		l.Println(v...)
	}
}

func (l *DebugLogger) Debugf(s string, v ...interface{}) {
	if l.Verbose {
		l.Printf(s, v...)
	}
}

// func (l *DebugLogger) Print(v ...interface{}) {
// 	log.Print(v...)
// }
//
// func (l *DebugLogger) Fatal(v ...interface{}) {
// 	log.Fatal(v...)
// }
//
// func (l *DebugLogger) Fatalf(a string, v ...interface{}) {
// 	log.Fatalf(a, v...)
// }

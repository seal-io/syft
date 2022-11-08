/*
Package log contains the singleton object and helper functions for facilitating logging within the syft library.
*/
package log

import (
	"github.com/anchore/syft/syft/logger"
	"github.com/sirupsen/logrus"
)

// Log is the singleton used to facilitate logging internally within syft
var Log logger.Logger = &nopLogger{}

// Errorf takes a formatted template string and template arguments for the error logging level.
func Errorf(format string, args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Errorf(format, args...)
}

// Error logs the given arguments at the error logging level.
func Error(args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Error(args...)
}

// Warnf takes a formatted template string and template arguments for the warning logging level.
func Warnf(format string, args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Warnf(format, args...)
}

// Warn logs the given arguments at the warning logging level.
func Warn(args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Warn(args...)
}

// Infof takes a formatted template string and template arguments for the info logging level.
func Infof(format string, args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Infof(format, args...)
}

// Info logs the given arguments at the info logging level.
func Info(args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Info(args...)
}

// Debugf takes a formatted template string and template arguments for the debug logging level.
func Debugf(format string, args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Debugf(format, args...)
}

// Debug logs the given arguments at the debug logging level.
func Debug(args ...interface{}) {
	logrus.WithField("analyzer", "seal-syft").Debug(args...)
}

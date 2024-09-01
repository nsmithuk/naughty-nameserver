package main

type logger struct{}

func (l *logger) Infof(format string, v ...interface{})    {}
func (l *logger) Debugf(format string, v ...interface{})   {}
func (l *logger) Warningf(format string, v ...interface{}) {}
func (l *logger) Errorf(format string, v ...interface{})   {}
func (l *logger) Fatalf(format string, v ...interface{})   {}

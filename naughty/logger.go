package naughty

//var Log Logger = defaultLogger{}
//
//type Logger interface {
//	Infof(format string, v ...interface{})
//	Debugf(format string, v ...interface{})
//	Warningf(format string, v ...interface{})
//	Errorf(format string, v ...interface{})
//	Fatalf(format string, v ...interface{})
//}
//
//type defaultLogger struct{}
//
//func (l defaultLogger) Infof(format string, v ...interface{}) {
//	fmt.Printf(format, v...)
//}
//func (l defaultLogger) Debugf(format string, v ...interface{}) {
//	fmt.Printf(format, v...)
//}
//func (l defaultLogger) Warningf(format string, v ...interface{}) {
//	fmt.Printf(format, v...)
//}
//func (l defaultLogger) Errorf(format string, v ...interface{}) {
//	fmt.Printf(format, v...)
//}
//func (l defaultLogger) Fatalf(format string, v ...interface{}) {
//	fmt.Printf(format, v...)
//	os.Exit(1)
//}

type Logger func(string)

// Default logging functions just black-hole the input.

var Query Logger = func(s string) {}
var Debug Logger = func(s string) {}
var Info Logger = func(s string) {}
var Warn Logger = func(s string) {}

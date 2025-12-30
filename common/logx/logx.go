package logx

import (
	"log/slog"
	"sync/atomic"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type nop struct{}

func (nop) Debug(string, ...any) {}
func (nop) Info(string, ...any)  {}
func (nop) Warn(string, ...any)  {}
func (nop) Error(string, ...any) {}

var current atomic.Value

func init() {
	current.Store(Logger(slog.Default()))
}

func L() Logger {
	return current.Load().(Logger)
}

func SetLogger(l Logger) {
	if l == nil {
		l = nop{}
	}
	current.Store(l)
}

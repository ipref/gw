/* Copyright (c) 2018-2020 Waldemar Augustyn */

package main

import (
	"fmt"
	golog "log"
	"os"
	"runtime"
	"strings"
)

const (
	TRACE = iota
	DEBUG
	INFO
	ERROR
	FATAL
	NONE
)

type Log struct {
	level uint
}

var log = Log{INFO}

func (l *Log) set(level uint, stamps bool) {

	l.level = level

	if stamps {
		golog.SetFlags(golog.Ltime | golog.Lmicroseconds)
	} else {
		golog.SetFlags(0)
	}
}

func (l *Log) fatal(msg string, params ...interface{}) {

	golog.Printf("F "+msg, params...)
	select {
	case goexit <- "fatal":
		select {}
	default: // if goexit not ready, just exit
		os.Exit(1)
	}
}

func (l *Log) err(msg string, params ...interface{}) {

	if l.level <= ERROR {
		golog.Printf("E "+msg, params...)
	}
}

func (l *Log) info(msg string, params ...interface{}) {

	if l.level <= INFO {
		golog.Printf("I "+msg, params...)
	}
}

func (l *Log) debug(msg string, params ...interface{}) {

	if len(cli.debug) == 0 {
		return
	}

	_, fname, line, ok := runtime.Caller(1)
	if !ok {
		return
	}

	bix := 0
	eix := len(fname)
	if ix := strings.LastIndex(fname, "/"); ix >= 0 {
		bix = ix + 1
	}
	if ix := strings.LastIndex(fname, "."); ix >= 0 {
		eix = ix
	}

	if cli.debug[fname[bix:eix]] || cli.debug["all"] {
		msg = fmt.Sprintf("%v(%v): ", fname[bix:], line) + msg
		golog.Printf("D "+msg, params...)
	}
}

func (l *Log) trace(msg string, params ...interface{}) {

	if l.level <= TRACE {
		golog.Printf("T "+msg, params...)
	}
}

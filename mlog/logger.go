/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package mlog

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

// localTimeEncoder encodes time.Time to local timezone string
func localTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Local().Format("2006-01-02 15:04:05"))
}

type LogConfig struct {
	// Level, See also zapcore.ParseLevel.
	Level string `yaml:"level"`

	// File that logger will be writen into.
	// Default is stderr.
	File string `yaml:"file"`

	// Production enables json output.
	Production bool `yaml:"production"`
}

var (
	stderr = zapcore.Lock(os.Stderr)
	lvl    = zap.NewAtomicLevelAt(zap.InfoLevel)
	// Use local timezone for global logger
	_globalEncoderConfig *zapcore.EncoderConfig
	l      *zap.Logger
	s      *zap.SugaredLogger

	nop = zap.NewNop()
)

func init() {
	// Use local timezone for global logger
	cfg := zap.NewDevelopmentEncoderConfig()
	cfg.EncodeTime = localTimeEncoder
	_globalEncoderConfig = &cfg
	l = zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(cfg), stderr, lvl))
	s = l.Sugar()
}

func NewLogger(lc LogConfig) (*zap.Logger, error) {
	lvl, err := zapcore.ParseLevel(lc.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	var out zapcore.WriteSyncer
	if lf := lc.File; len(lf) > 0 {
		f, _, err := zap.Open(lf)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		out = zapcore.Lock(f)
	} else {
		out = stderr
	}

	// Use local timezone for timestamps
	productionConfig := zap.NewProductionEncoderConfig()
	productionConfig.EncodeTime = localTimeEncoder

	developmentConfig := zap.NewDevelopmentEncoderConfig()
	developmentConfig.EncodeTime = localTimeEncoder

	if lc.Production {
		return zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(productionConfig), out, lvl)), nil
	}
	return zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(developmentConfig), out, lvl)), nil
}

// L is a global logger.
func L() *zap.Logger {
	return l
}

// SetLevel sets the log level for the global logger.
func SetLevel(l zapcore.Level) {
	lvl.SetLevel(l)
}

// S is a global logger.
func S() *zap.SugaredLogger {
	return s
}

// Nop is a logger that never writes out logs.
func Nop() *zap.Logger {
	return nop
}

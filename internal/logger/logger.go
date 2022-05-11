// Copyright (c) 2022 The Linna Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: randyma 435420057@qq.com
// Date: 2022-05-11 10:19:18
// LastEditors: randyma 435420057@qq.com
// LastEditTime: 2022-05-11 10:19:20
// FilePath: \linna\internal\logger\logger.go
// Description: 日志处理与声明 Reference: https://github.com/heroiclabs/nakama

package logger

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// 定义日志输出格式
type LoggingFormat int8

const (
	// JSONFormat json格式输出
	JSONFormat LoggingFormat = iota - 1

	// StackdriverFormat Stackdriver
	StackdriverFormat
)

// Configuration 日志配置信息
type Configuration struct {
	Level      string `yaml:"level" json:"level" usage:"Log level to set. Valid values are 'debug', 'info', 'warn', 'error'. Default 'info'."`
	Stdout     bool   `yaml:"stdout" json:"stdout" usage:"Log to standard console output (as well as to a file if set). Default true."`
	File       string `yaml:"file" json:"file" usage:"Log output to a file (as well as stdout if set). Make sure that the directory and the file is writable."`
	Rotation   bool   `yaml:"rotation" json:"rotation" usage:"Rotate log files. Default is false."`
	MaxSize    int    `yaml:"max_size" json:"max_size" usage:"The maximum size in megabytes of the log file before it gets rotated. It defaults to 100 megabytes."`
	MaxAge     int    `yaml:"max_age" json:"max_age" usage:"The maximum number of days to retain old log files based on the timestamp encoded in their filename. The default is not to remove old log files based on age."`
	MaxBackups int    `yaml:"max_backups" json:"max_backups" usage:"The maximum number of old log files to retain. The default is to retain all old log files (though MaxAge may still cause them to get deleted.)"`
	LocalTime  bool   `yaml:"local_time" json:"local_time" usage:"This determines if the time used for formatting the timestamps in backup files is the computer's local time. The default is to use UTC time."`
	Compress   bool   `yaml:"compress" json:"compress" usage:"This determines if the rotated log files should be compressed using gzip."`
	Format     string `yaml:"format" json:"format" usage:"Set logging output format. Can either be 'JSON' or 'Stackdriver'. Default is 'JSON'."`
}

// Check 检查配置文件
func (c *Configuration) Check() error {
	return nil
}

// New 创建日志控制器
func New(logger *zap.Logger, config Configuration) (*zap.Logger, *zap.Logger) {
	zapLevel, err := switchZapLevel(config.Level)
	if err != nil {
		logger.Fatal(err.Error())
	}

	format, err := switchLoggingFormat(config.Format)
	if err != nil {
		logger.Fatal(err.Error())
	}

	consoleLogger := NewJSONLogger(os.Stdout, zapLevel, format)
	var fileLogger *zap.Logger
	if config.Rotation {
		fileLogger = NewRotatingJSONFileLogger(consoleLogger, config, zapLevel, format)
	} else {
		fileLogger = NewJSONFileLogger(consoleLogger, config, zapLevel, format)
	}

	if fileLogger != nil {
		multiLogger := NewMultiLogger(consoleLogger, fileLogger)

		if config.Stdout {
			RedirectStdLog(multiLogger)
			return multiLogger, multiLogger
		}

		RedirectStdLog(fileLogger)
		return fileLogger, multiLogger
	}

	RedirectStdLog(consoleLogger)
	return consoleLogger, consoleLogger
}

// NewJSONLogger 创建json格式输出日志
func NewJSONLogger(output *os.File, level zapcore.Level, format LoggingFormat) *zap.Logger {
	jsonEncoder := newJSONEncoder(format)

	core := zapcore.NewCore(jsonEncoder, zapcore.Lock(output), level)
	return zap.New(core, zap.AddCaller())
}

// NewRotatingJSONFileLogger 创建滚动式日志文件存储
func NewRotatingJSONFileLogger(logger *zap.Logger, config Configuration, level zapcore.Level, format LoggingFormat) *zap.Logger {
	if len(config.File) == 0 {
		logger.Fatal("rotating log file is enabled but log file name is empty")
		return nil
	}

	logDir := filepath.Dir(config.File)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.Fatal("could not create log directory", zap.Error(err))
			return nil
		}
	}

	jsonEncoder := newJSONEncoder(format)

	// lumberjack.Logger is already safe for concurrent use, so we don't need to lock it.
	writeSyncer := zapcore.AddSync(&lumberjack.Logger{
		Filename:   config.File,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		LocalTime:  config.LocalTime,
		Compress:   config.Compress,
	})

	core := zapcore.NewCore(jsonEncoder, writeSyncer, level)
	return zap.New(core, zap.AddCaller())
}

// NewJSONFileLogger file
func NewJSONFileLogger(logger *zap.Logger, config Configuration, level zapcore.Level, format LoggingFormat) *zap.Logger {
	if len(config.File) == 0 {
		return nil
	}

	output, err := os.OpenFile(config.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logger.Fatal("could not create log file", zap.Error(err))
		return nil
	}

	return NewJSONLogger(output, level, format)
}

// NewMultiLogger 多日志创建
func NewMultiLogger(loggers ...*zap.Logger) *zap.Logger {
	cores := make([]zapcore.Core, 0, len(loggers))
	for _, logger := range loggers {
		cores = append(cores, logger.Core())
	}

	teeCore := zapcore.NewTee(cores...)
	options := []zap.Option{zap.AddCaller()}
	return zap.New(teeCore, options...)
}

func newJSONEncoder(format LoggingFormat) zapcore.Encoder {
	if format == StackdriverFormat {
		return zapcore.NewJSONEncoder(zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "severity",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			EncodeLevel:    StackdriverLevelEncoder,
			EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		})
	}

	return zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})
}

// StackdriverLevelEncoder  stackdriver Level encoder
func StackdriverLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	switch l {
	case zapcore.DebugLevel:
		enc.AppendString("DEBUG")
	case zapcore.InfoLevel:
		enc.AppendString("INFO")
	case zapcore.WarnLevel:
		enc.AppendString("WARNING")
	case zapcore.ErrorLevel:
		enc.AppendString("ERROR")
	case zapcore.DPanicLevel:
		enc.AppendString("CRITICAL")
	case zapcore.PanicLevel:
		enc.AppendString("CRITICAL")
	case zapcore.FatalLevel:
		enc.AppendString("CRITICAL")
	default:
		enc.AppendString("DEFAULT")
	}
}

func switchZapLevel(level string) (zapcore.Level, error) {
	zapLevel := zapcore.InfoLevel
	switch strings.ToLower(level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		return zapLevel, errors.New("logger level invalid, must be one of: DEBUG, INFO, WARN, or ERROR")
	}

	return zapLevel, nil
}

func switchLoggingFormat(format string) (LoggingFormat, error) {
	logformat := JSONFormat
	switch strings.ToLower(format) {
	case "":
		fallthrough
	case "json":
		logformat = JSONFormat
	case "stackdriver":
		logformat = StackdriverFormat
	default:
		return JSONFormat, errors.New("logger mode invalid, must be one of: '', 'json', or 'stackdriver")
	}

	return logformat, nil
}

type RedirectStdLogWriter struct {
	logger *zap.Logger
}

func (r *RedirectStdLogWriter) Write(p []byte) (int, error) {
	s := string(bytes.TrimSpace(p))
	if strings.HasPrefix(s, "http: panic serving") {
		r.logger.Error(s)
	} else {
		r.logger.Info(s)
	}
	return len(s), nil
}

func RedirectStdLog(logger *zap.Logger) {
	log.SetFlags(0)
	log.SetPrefix("")
	skipLogger := logger.WithOptions(zap.AddCallerSkip(3))
	log.SetOutput(&RedirectStdLogWriter{skipLogger})
}

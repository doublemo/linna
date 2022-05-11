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
// Date: 2022-05-11 13:04:16
// LastEditors: randyma 435420057@qq.com
// LastEditTime: 2022-05-11 13:04:25
// FilePath: \linna\internal\logger\instance.go
// Description:初始化默认日志输出
package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	defaultConsoleLogger *zap.Logger
	defaultFileLogger    *zap.Logger
)

// Logger 获取日志
func Logger() (*zap.Logger, *zap.Logger) {
	if defaultConsoleLogger == nil {
		defaultConsoleLogger = NewJSONLogger(os.Stdout, zapcore.InfoLevel, JSONFormat)
	}

	if defaultFileLogger == nil {
		defaultFileLogger = defaultConsoleLogger
	}

	return defaultConsoleLogger, defaultFileLogger
}

// Initializer 初始化日志
func Initializer(consoleLogger, fileLogger *zap.Logger) {
	defaultConsoleLogger = consoleLogger
	defaultFileLogger = fileLogger
}

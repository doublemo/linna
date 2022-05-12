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
// Author: randyma
// Date: 2022-05-12 18:07:10
// LastEditors: randyma
// LastEditTime: 2022-05-12 18:07:16
// Description:
// Reference: https://github.com/heroiclabs/nakama-common

package runtime

import (
	"context"
	"database/sql"
)

// Logger公开了一个日志框架以在模块中使用。它公开了特定于级别的日志函数和一组通用函数，以实现兼容性
type Logger interface {

	// Debug 调试
	Debug(format string, v ...interface{})

	// Info 信息
	Info(format string, v ...interface{})

	// Warn 警告
	Warn(format string, v ...interface{})

	// Error 错误
	Error(format string, v ...interface{})

	// WithField 返回设置了指定字段的记录器，以便它们包含在后续的日志调用中
	WithField(key string, v interface{}) Logger

	// WithFields 返回设置了指定字段的记录器，以便在后续日志调用中包含这些字段。
	WithFields(fields map[string]interface{}) Logger

	// Fields 返回此记录器中设置的字段
	Fields() map[string]interface{}
}

// Initializer 初始化器用于向服务器注册各种回调函数。
// 当服务器在server start上加载模块时调用函数时，InitModule函数可以将其作为输入参数使用。
//
// 注意：您不能缓存对它的引用，并在以后再次使用它，因为这可能会产生意外的副作用
type Initializer interface {
	RegisterRpc(id string, fn func(ctx context.Context, logger Logger, db *sql.DB, m LinnaModule, payload string) (string, error)) error
}

// LinnaModule 模块功能接口
type LinnaModule interface {
	AuthenticateApple(ctx context.Context, token, username string, create bool) (string, string, bool, error)
	AuthenticateCustom(ctx context.Context, id, username string, create bool) (string, string, bool, error)
	AuthenticateDevice(ctx context.Context, id, username string, create bool) (string, string, bool, error)
	AuthenticateEmail(ctx context.Context, email, password, username string, create bool) (string, string, bool, error)
	AuthenticateFacebook(ctx context.Context, token string, importFriends bool, username string, create bool) (string, string, bool, error)
	AuthenticateFacebookInstantGame(ctx context.Context, signedPlayerInfo string, username string, create bool) (string, string, bool, error)
	AuthenticateGameCenter(ctx context.Context, playerID, bundleID string, timestamp int64, salt, signature, publicKeyUrl, username string, create bool) (string, string, bool, error)
	AuthenticateGoogle(ctx context.Context, token, username string, create bool) (string, string, bool, error)
	AuthenticateSteam(ctx context.Context, token, username string, create bool) (string, string, bool, error)

	AuthenticateTokenGenerate(userID, username string, exp int64, vars map[string]string) (string, int64, error)
}

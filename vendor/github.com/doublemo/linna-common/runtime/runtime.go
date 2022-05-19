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

package runtime

import (
	"context"
	"database/sql"
)

type RuntimeContextValueKT string

func (k RuntimeContextValueKT) String() string {
	return string(k)
}

const (
	RUNTIME_CTX_ENV              RuntimeContextValueKT = "env"              // 环境变量Key
	RUNTIME_CTX_MODE             RuntimeContextValueKT = "execution_mode"   // 运行时模式
	RUNTIME_CTX_NODE             RuntimeContextValueKT = "node"             // 节点名称
	RUNTIME_CTX_HEADERS          RuntimeContextValueKT = "headers"          // HTTP头
	RUNTIME_CTX_QUERY_PARAMS     RuntimeContextValueKT = "query_params"     // HTTP query
	RUNTIME_CTX_USER_ID          RuntimeContextValueKT = "user_id"          // 用户ID
	RUNTIME_CTX_USERNAME         RuntimeContextValueKT = "username"         // 用户名称
	RUNTIME_CTX_VARS             RuntimeContextValueKT = "vars"             // 变量存储
	RUNTIME_CTX_USER_SESSION_EXP RuntimeContextValueKT = "user_session_exp" // 用户会话过期时间
	RUNTIME_CTX_SESSION_ID       RuntimeContextValueKT = "session_id"       // 用户会话ID
	RUNTIME_CTX_LANG             RuntimeContextValueKT = "lang"             // 用户语言
	RUNTIME_CTX_CLIENT_IP        RuntimeContextValueKT = "client_ip"        // 客户端IP
	RUNTIME_CTX_CLIENT_PORT      RuntimeContextValueKT = "client_port"      // 客户端端口
)

/*
Error is used to indicate a failure in code. The message and code are returned to the client.
If an Error is used as response for a HTTP/gRPC request, then the server tries to use the error value as the gRPC error code. This will in turn translate to HTTP status codes.
For more information, please have a look at the following:
	https://github.com/grpc/grpc-go/blob/master/codes/codes.go
	https://github.com/grpc-ecosystem/grpc-gateway/blob/master/runtime/errors.go
	https://golang.org/pkg/net/http/
*/
type Error struct {
	Message string
	Code    int
}

// Error returns the encapsulated error message.
func (e *Error) Error() string {
	return e.Message
}

/*
NewError returns a new error. The message and code are sent directly to the client. The code field is also optionally translated to gRPC/HTTP code.
	runtime.NewError("Server unavailable", 14) // 14 = Unavailable = 503 HTTP status code
*/
func NewError(message string, code int) *Error {
	return &Error{Message: message, Code: code}
}

/*
Logger exposes a logging framework to use in modules. It exposes level-specific logging functions and a set of common functions for compatibility.
*/
type Logger interface {
	/*
		Log a message with optional arguments at DEBUG level. Arguments are handled in the manner of fmt.Printf.
	*/
	Debug(format string, v ...interface{})
	/*
		Log a message with optional arguments at INFO level. Arguments are handled in the manner of fmt.Printf.
	*/
	Info(format string, v ...interface{})
	/*
		Log a message with optional arguments at WARN level. Arguments are handled in the manner of fmt.Printf.
	*/
	Warn(format string, v ...interface{})
	/*
		Log a message with optional arguments at ERROR level. Arguments are handled in the manner of fmt.Printf.
	*/
	Error(format string, v ...interface{})
	/*
		Return a logger with the specified field set so that they are included in subsequent logging calls.
	*/
	WithField(key string, v interface{}) Logger
	/*
		Return a logger with the specified fields set so that they are included in subsequent logging calls.
	*/
	WithFields(fields map[string]interface{}) Logger
	/*
		Returns the fields set in this logger.
	*/
	Fields() map[string]interface{}
}

/*
Initializer is used to register various callback functions with the server.
It is made available to the InitModule function as an input parameter when the function is invoked by the server when loading the module on server start.
NOTE: You must not cache the reference to this and reuse it as a later point as this could have unintended side effects.
*/
type Initializer interface {
	RegisterRpc(id string, fn func(ctx context.Context, logger Logger, db *sql.DB, na LinnaModule, payload string) (string, error)) error
}

// LinnaModule 模块功能接口
type LinnaModule interface {
	Authenticate(ctx context.Context, token, username string, create bool) (string, string, bool, error)
}

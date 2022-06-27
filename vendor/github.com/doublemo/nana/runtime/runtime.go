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

package runtime

import (
	"context"
	"database/sql"

	"github.com/doublemo/nana/rtapi"
)

// 定义运行时常量
const (
	// All available environmental variables made available to the runtime environment.
	// This is useful to store API keys and other secrets which may be different between servers run in production and in development.
	//   envs := ctx.Value(runtime.RUNTIME_CTX_ENV).(map[string]string)
	// This can always be safely cast into a `map[string]string`.
	RUNTIME_CTX_ENV = "env"

	// The node ID where the current runtime context is executing.
	RUNTIME_CTX_NODE = "node"

	// Http headers. Only applicable to HTTP RPC requests.
	RUNTIME_CTX_HEADERS = "headers"

	// Query params that was passed through from HTTP request.
	RUNTIME_CTX_QUERY_PARAMS = "query_params"

	// The user ID associated with the execution context.
	RUNTIME_CTX_USER_ID = "user_id"

	// The username associated with the execution context.
	RUNTIME_CTX_USERNAME = "username"

	// Variables stored in the user's session token.
	RUNTIME_CTX_VARS = "vars"

	// The user session expiry in seconds associated with the execution context.
	RUNTIME_CTX_USER_SESSION_EXP = "user_session_exp"

	// The user session associated with the execution context.
	RUNTIME_CTX_SESSION_ID = "session_id"

	// The user session's lang value, if one is set.
	RUNTIME_CTX_LANG = "lang"

	// The IP address of the client making the request.
	RUNTIME_CTX_CLIENT_IP = "client_ip"

	// The port number of the client making the request.
	RUNTIME_CTX_CLIENT_PORT = "client_port"
)

// 定义模块入口名称
const INIT_MODULE_FUNC_NAME = "InitModule"

type Initializer interface {
	RegisterRpc(id string, fn func(ctx context.Context, logger Logger, db *sql.DB, m Module, payload string) (string, error)) error
	RegisterBeforeRt(id string, fn func(ctx context.Context, logger Logger, db *sql.DB, m Module, envelope *rtapi.Envelope) (*rtapi.Envelope, error)) error
	RegisterAfterRt(id string, fn func(ctx context.Context, logger Logger, db *sql.DB, m Module, out, in *rtapi.Envelope) error) error
}

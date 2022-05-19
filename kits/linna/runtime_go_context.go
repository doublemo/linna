// Copyright (c) 2021 The Nakama Authors.
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
// Date: 2022-05-09 09:55:26
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:41:12
// Description:

package linna

import (
	"context"

	"github.com/doublemo/linna-common/runtime"
)

// NewRuntimeGoContext 创建Go运行时上下文
func NewRuntimeGoContext(ctx context.Context, mode RuntimeExecutionMode, c *RuntimeContextConfiguration) context.Context {
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_ENV, c.Env)
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_MODE, mode.String())
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_NODE, c.Node)

	if c.Headers != nil {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_HEADERS, c.Headers)
	}

	if c.QueryParams != nil {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_QUERY_PARAMS, c.QueryParams)
	}

	if c.UserID != 0 {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USER_ID, c.UserID)
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USERNAME, c.Username)
		if c.Vars != nil {
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_VARS, c.Vars)
		}

		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USER_SESSION_EXP, c.SessionExpiry)
		if c.SessionID != "" {
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_SESSION_ID, c.SessionID)
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_LANG, c.Lang)
		}
	}

	if c.ClientIP != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_CLIENT_IP, c.ClientIP)
	}
	if c.ClientPort != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_CLIENT_PORT, c.ClientPort)
	}

	return ctx
}

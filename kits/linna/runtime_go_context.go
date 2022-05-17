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

// RuntimeGoContextOptions Go运行时上下文创建参数项
type RuntimeGoContextOptions struct {
	Node          string            // 节点
	Env           map[string]string // 环境变量
	Headers       map[string]string // 头信息
	QueryParams   map[string]string // 参数
	SeessionID    string            // 会话ID
	SessionExpiry int64             // 会话过期时间
	UserID        string            // 用户ID
	UserName      string            // 用户
	Vars          map[string]string //
	ClientIP      string            // 客户IP
	ClientPort    string            // 客户端端口
	Lang          string            // 语言
}

// NewRuntimeGoContextOptions 参数
func NewRuntimeGoContextOptions() *RuntimeGoContextOptions {
	return &RuntimeGoContextOptions{
		Env: make(map[string]string),
	}
}

// NewRuntimeGoContext 创建Go运行时上下文
func NewRuntimeGoContext(ctx context.Context, mode RuntimeExecutionMode, options *RuntimeGoContextOptions) context.Context {
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_ENV, options.Env)
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_MODE, mode.String())
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_NODE, options.Node)

	if options.Headers != nil {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_HEADERS, options.Headers)
	}

	if options.QueryParams != nil {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_QUERY_PARAMS, options.QueryParams)
	}

	if options.UserID != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USER_ID, options.UserID)
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USERNAME, options.UserName)
		if options.Vars != nil {
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_VARS, options.Vars)
		}

		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USER_SESSION_EXP, options.SessionExpiry)
		if options.SeessionID != "" {
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_SESSION_ID, options.SeessionID)
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_LANG, options.Lang)
		}
	}

	if options.ClientIP != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_CLIENT_IP, options.ClientIP)
	}
	if options.ClientPort != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_CLIENT_PORT, options.ClientPort)
	}

	return ctx
}

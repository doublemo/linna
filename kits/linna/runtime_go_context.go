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

package linna

import (
	"context"

	"github.com/doublemo/nana/runtime"
)

type RuntimeGoContextValues struct {
	*RuntimeRpcValues
	Env  map[string]string
	Node string
}

func NewRuntimeGoContext(ctx context.Context, values *RuntimeGoContextValues) context.Context {
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_ENV, values.Env)
	ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_NODE, values.Node)
	if values.Headers != nil {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_HEADERS, values.Headers)
	}

	if values.QueryParams != nil {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_QUERY_PARAMS, values.QueryParams)
	}

	if len(values.UserId) > 0 {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USER_ID, values.UserId)
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USERNAME, values.Username)
		if values.Vars != nil {
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_VARS, values.Vars)
		}

		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_USER_SESSION_EXP, values.Expiry)
		if values.SessionID != "" {
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_SESSION_ID, values.SessionID)
			ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_LANG, values.Lang)
		}
	}

	if values.ClientIP != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_CLIENT_IP, values.ClientIP)
	}
	if values.ClientPort != "" {
		ctx = context.WithValue(ctx, runtime.RUNTIME_CTX_CLIENT_PORT, values.ClientPort)
	}
	return ctx
}

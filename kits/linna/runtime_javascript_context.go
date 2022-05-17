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
// Date: 2022-05-16 18:44:47
// LastEditors: randyma
// LastEditTime: 2022-05-16 18:44:52
// Description: Javascript 上下文

package linna

import (
	"fmt"

	"github.com/dop251/goja"
	"github.com/doublemo/linna-common/runtime"
)

// RuntimeJSContextOptions JS运行时上下文创建参数项
type RuntimeJSContextOptions struct {
	Node          string              // 节点
	Env           goja.Value          // 环境变量
	Headers       map[string][]string // 头信息
	QueryParams   map[string][]string // 参数
	SeessionID    string              // 会话ID
	SessionExpiry int64               // 会话过期时间
	UserID        string              // 用户ID
	Username      string              // 用户
	Vars          map[string]string   //
	ClientIP      string              // 客户IP
	ClientPort    string              // 客户端端口
	Lang          string              // 语言
}

// NewRuntimeJsContext 创建Javascript运行时上下文
func NewRuntimeJsContext(r *goja.Runtime, mode RuntimeExecutionMode, option *RuntimeJSContextOptions) *goja.Object {
	ctxObj := r.NewObject()
	ctxObj.Set(runtime.RUNTIME_CTX_NODE.String(), option.Node)
	ctxObj.Set(runtime.RUNTIME_CTX_ENV.String(), option.Env)
	ctxObj.Set(runtime.RUNTIME_CTX_MODE.String(), mode.String())

	if option.Headers != nil {
		ctxObj.Set(runtime.RUNTIME_CTX_HEADERS.String(), option.Headers)
	}

	if option.QueryParams != nil {
		ctxObj.Set(runtime.RUNTIME_CTX_QUERY_PARAMS.String(), option.QueryParams)
	}

	if option.Vars != nil {
		ctxObj.Set(runtime.RUNTIME_CTX_VARS.String(), option.Vars)
	}

	if option.SessionExpiry != 0 {
		ctxObj.Set(runtime.RUNTIME_CTX_USER_SESSION_EXP.String(), option.SessionExpiry)
	}

	if option.UserID != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_USER_ID.String(), option.UserID)
	}

	if option.SeessionID != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_SESSION_ID.String(), option.SeessionID)
		ctxObj.Set(runtime.RUNTIME_CTX_LANG.String(), option.Lang)
	}

	if option.Username != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_USERNAME.String(), option.Username)
	}

	if option.ClientIP != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_CLIENT_IP.String(), option.ClientIP)
	}
	if option.ClientPort != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_CLIENT_PORT.String(), option.ClientPort)
	}
	return ctxObj
}

func NewRuntimeJsInitContext(r *goja.Runtime, node string, env map[string]string) *goja.Object {
	ctxObj := r.NewObject()
	ctxObj.Set(runtime.RUNTIME_CTX_NODE.String(), node)
	ctxObj.Set(runtime.RUNTIME_CTX_ENV.String(), env)

	return ctxObj
}

func RuntimeJsConvertJsValue(jv interface{}) interface{} {
	switch v := jv.(type) {
	case map[string]interface{}:
		newMap := make(map[string]interface{}, len(v))
		for mapKey, mapValue := range v {
			newMap[mapKey] = RuntimeJsConvertJsValue(mapValue)
		}
		return newMap

	case []interface{}:
		newSlice := make([]interface{}, len(v))
		for i, sliceValue := range v {
			newSlice[i] = RuntimeJsConvertJsValue(sliceValue)
		}
		return newSlice

	case func(goja.FunctionCall) goja.Value:
		return fmt.Sprintf("function: %p", v)

	default:
		return v
	}
}

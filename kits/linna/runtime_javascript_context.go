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

// NewRuntimeJsContext 创建Javascript运行时上下文
func NewRuntimeJsContext(r *goja.Runtime, mode RuntimeExecutionMode, c *RuntimeContextConfiguration) *goja.Object {
	ctxObj := r.NewObject()
	ctxObj.Set(runtime.RUNTIME_CTX_NODE.String(), c.Node)
	ctxObj.Set(runtime.RUNTIME_CTX_ENV.String(), r.ToValue(c.Env))
	ctxObj.Set(runtime.RUNTIME_CTX_MODE.String(), mode.String())

	if c.Headers != nil {
		ctxObj.Set(runtime.RUNTIME_CTX_HEADERS.String(), c.Headers)
	}

	if c.QueryParams != nil {
		ctxObj.Set(runtime.RUNTIME_CTX_QUERY_PARAMS.String(), c.QueryParams)
	}

	if c.Vars != nil {
		ctxObj.Set(runtime.RUNTIME_CTX_VARS.String(), c.Vars)
	}

	if c.SessionExpiry != 0 {
		ctxObj.Set(runtime.RUNTIME_CTX_USER_SESSION_EXP.String(), c.SessionExpiry)
	}

	ctxObj.Set(runtime.RUNTIME_CTX_USER_ID.String(), c.UserID)
	if c.SessionID != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_SESSION_ID.String(), c.SessionID)
		ctxObj.Set(runtime.RUNTIME_CTX_LANG.String(), c.Lang)
	}

	if c.Username != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_USERNAME.String(), c.Username)
	}

	if c.ClientIP != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_CLIENT_IP.String(), c.ClientIP)
	}
	if c.ClientPort != "" {
		ctxObj.Set(runtime.RUNTIME_CTX_CLIENT_PORT.String(), c.ClientPort)
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

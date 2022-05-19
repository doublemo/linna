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
// Date: 2022-05-18 15:49:59
// LastEditors: randyma
// LastEditTime: 2022-05-18 15:57:55
// Description: lua 上下文

package linna

import (
	"fmt"
	"time"

	"github.com/doublemo/linna-common/runtime"
	lua "github.com/doublemo/linna/cores/gopher-lua"
)

// NewRuntimeLuaContext lua 上下文
func NewRuntimeLuaContext(l *lua.LState, mode RuntimeExecutionMode, c *RuntimeContextConfiguration) *lua.LTable {
	env := RuntimeLuaConvertMapString(l, c.Env)
	size := 3
	if c.UserID != 0 {
		size += 3
		if c.SessionID != "" {
			size++
		}
	}

	if c.ClientIP != "" {
		size++
	}

	if c.ClientPort != "" {
		size++
	}

	lt := l.CreateTable(0, size)
	lt.RawSetString(runtime.RUNTIME_CTX_ENV.String(), env)
	lt.RawSetString(runtime.RUNTIME_CTX_MODE.String(), lua.LString(mode.String()))
	lt.RawSetString(runtime.RUNTIME_CTX_NODE.String(), lua.LString(c.Node))
	if c.Headers == nil {
		lt.RawSetString(runtime.RUNTIME_CTX_HEADERS.String(), l.CreateTable(0, 0))
	} else {
		lt.RawSetString(runtime.RUNTIME_CTX_HEADERS.String(), RuntimeLuaConvertValue(l, c.Headers))
	}

	if c.QueryParams != nil {
		lt.RawSetString(runtime.RUNTIME_CTX_QUERY_PARAMS.String(), l.CreateTable(0, 0))
	} else {
		lt.RawSetString(runtime.RUNTIME_CTX_QUERY_PARAMS.String(), RuntimeLuaConvertValue(l, c.QueryParams))
	}

	if c.UserID != 0 {
		lt.RawSetString(runtime.RUNTIME_CTX_USER_ID.String(), lua.LNumber(c.UserID))
		lt.RawSetString(runtime.RUNTIME_CTX_USERNAME.String(), lua.LString(c.Username))
		if c.Vars != nil {
			vt := l.CreateTable(0, len(c.Vars))
			for k, v := range c.Vars {
				vt.RawSetString(k, lua.LString(v))
			}

			lt.RawSetString(runtime.RUNTIME_CTX_VARS.String(), vt)
		}

		lt.RawSetString(runtime.RUNTIME_CTX_USER_SESSION_EXP.String(), lua.LNumber(c.SessionExpiry))
		if c.SessionID != "" {
			lt.RawSetString(runtime.RUNTIME_CTX_SESSION_ID.String(), lua.LString(c.SessionID))

			// Lang is never reported without session ID.
			lt.RawSetString(runtime.RUNTIME_CTX_LANG.String(), lua.LString(c.Lang))
		}
	}

	if c.ClientIP != "" {
		lt.RawSetString(runtime.RUNTIME_CTX_CLIENT_IP.String(), lua.LString(c.ClientIP))
	}
	if c.ClientPort != "" {
		lt.RawSetString(runtime.RUNTIME_CTX_CLIENT_PORT.String(), lua.LString(c.ClientPort))
	}

	return lt
}

func RuntimeLuaConvertMapString(l *lua.LState, data map[string]string) *lua.LTable {
	lt := l.CreateTable(0, len(data))

	for k, v := range data {
		lt.RawSetString(k, RuntimeLuaConvertValue(l, v))
	}

	return lt
}

func RuntimeLuaConvertMap(l *lua.LState, data map[string]interface{}) *lua.LTable {
	lt := l.CreateTable(0, len(data))

	for k, v := range data {
		lt.RawSetString(k, RuntimeLuaConvertValue(l, v))
	}

	return lt
}

func RuntimeLuaConvertMapInt64(l *lua.LState, data map[string]int64) *lua.LTable {
	lt := l.CreateTable(0, len(data))

	for k, v := range data {
		lt.RawSetString(k, RuntimeLuaConvertValue(l, v))
	}

	return lt
}

func RuntimeLuaConvertLuaTable(lv *lua.LTable) map[string]interface{} {
	returnData, _ := RuntimeLuaConvertLuaValue(lv).(map[string]interface{})
	return returnData
}

func RuntimeLuaConvertValue(l *lua.LState, val interface{}) lua.LValue {
	if val == nil {
		return lua.LNil
	}

	// Types looked up from:
	// https://golang.org/pkg/encoding/json/#Unmarshal
	// https://developers.google.com/protocol-buffers/docs/proto3#scalar
	// More types added based on observations.
	switch v := val.(type) {
	case bool:
		return lua.LBool(v)
	case string:
		return lua.LString(v)
	case []byte:
		return lua.LString(v)
	case float32:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case int:
		return lua.LNumber(v)
	case int32:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case uint32:
		return lua.LNumber(v)
	case uint64:
		return lua.LNumber(v)
	case map[string][]string:
		lt := l.CreateTable(0, len(v))
		for k, v := range v {
			lt.RawSetString(k, RuntimeLuaConvertValue(l, v))
		}
		return lt
	case map[string]string:
		return RuntimeLuaConvertMapString(l, v)
	case map[string]int64:
		return RuntimeLuaConvertMapInt64(l, v)
	case map[string]interface{}:
		return RuntimeLuaConvertMap(l, v)
	case []string:
		lt := l.CreateTable(len(val.([]string)), 0)
		for k, v := range v {
			lt.RawSetInt(k+1, lua.LString(v))
		}
		return lt
	case []interface{}:
		lt := l.CreateTable(len(val.([]interface{})), 0)
		for k, v := range v {
			lt.RawSetInt(k+1, RuntimeLuaConvertValue(l, v))
		}
		return lt
	case time.Time:
		return lua.LNumber(v.UTC().Unix())
	case nil:
		return lua.LNil
	default:
		// Never return an actual Go `nil` or it will cause nil pointer dereferences inside gopher-lua.
		return lua.LNil
	}
}

func RuntimeLuaConvertLuaValue(lv lua.LValue) interface{} {
	// Taken from: https://github.com/yuin/gluamapper/blob/master/gluamapper.go#L79
	switch v := lv.(type) {
	case *lua.LNilType:
		return nil
	case lua.LBool:
		return bool(v)
	case lua.LString:
		return string(v)
	case lua.LNumber:
		vf := float64(v)
		vi := int64(v)
		if vf == float64(vi) {
			// If it's a whole number use an actual integer type.
			return vi
		}
		return vf
	case *lua.LTable:
		maxn := v.MaxN()
		if maxn == 0 {
			// Table.
			ret := make(map[string]interface{})
			v.ForEach(func(key, value lua.LValue) {
				keyStr := fmt.Sprint(RuntimeLuaConvertLuaValue(key))
				ret[keyStr] = RuntimeLuaConvertLuaValue(value)
			})
			return ret
		}
		// Array.
		ret := make([]interface{}, 0, maxn)
		for i := 1; i <= maxn; i++ {
			ret = append(ret, RuntimeLuaConvertLuaValue(v.RawGetInt(i)))
		}
		return ret
	case *lua.LFunction:
		return v.String()
	default:
		return v
	}
}

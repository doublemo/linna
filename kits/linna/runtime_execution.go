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
// Date: 2022-05-18 10:15:02
// LastEditors: randyma
// LastEditTime: 2022-05-18 11:18:53
// Description: 通用类型定义

package linna

import (
	"context"
	"reflect"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

type RuntimeExecution struct {
	sync.RWMutex
	rpc                   map[string]RuntimeRpcFunction
	beforeRtFunctions     map[string]RuntimeBeforeRtFunction
	afterRtFunctions      map[string]RuntimeAfterRtFunction
	beforeReqFunctions    *RuntimeBeforeReqFunctions
	afterReqFunctions     *RuntimeAfterReqFunctions
	eventFunctions        []RuntimeEventFunction
	sessionStartFunctions []RuntimeEventFunction
	sessionEndFunctions   []RuntimeEventFunction
}

func (re *RuntimeExecution) GetRPC(key string) (RuntimeRpcFunction, bool) {
	re.RLock()
	defer re.RUnlock()
	fn, ok := re.rpc[key]
	return fn, ok
}

func (re *RuntimeExecution) RegisterRPC(key string, fn RuntimeRpcFunction) {
	re.Lock()
	re.rpc[key] = fn
	re.Unlock()
}

func (re *RuntimeExecution) CountRPC() (count int) {
	re.RLock()
	count = len(re.rpc)
	re.RUnlock()
	return
}

func (re *RuntimeExecution) ScanRPC(fn func(k string, v RuntimeRpcFunction)) {
	re.RLock()
	for rk, rv := range re.rpc {
		re.RUnlock()
		fn(rk, rv)
		re.RLock()
	}
	re.RUnlock()
}

func (re *RuntimeExecution) RegisterBeforeRt(key string, fn RuntimeBeforeRtFunction) {
	re.Lock()
	re.beforeRtFunctions[key] = fn
	re.Unlock()
}

func (re *RuntimeExecution) CountBeforeRt() (count int) {
	re.RLock()
	count = len(re.beforeRtFunctions)
	re.RUnlock()
	return
}

func (re *RuntimeExecution) ScanBeforeRt(fn func(k string, v RuntimeBeforeRtFunction)) {
	re.RLock()
	for rk, rv := range re.beforeRtFunctions {
		re.RUnlock()
		fn(rk, rv)
		re.RLock()
	}
	re.RUnlock()
}

func (re *RuntimeExecution) RegisterAfterRt(key string, fn RuntimeAfterRtFunction) {
	re.Lock()
	re.afterRtFunctions[key] = fn
	re.Unlock()
}

func (re *RuntimeExecution) CountAfterRt() (count int) {
	re.RLock()
	count = len(re.afterRtFunctions)
	re.RUnlock()
	return
}

func (re *RuntimeExecution) ScanAfterRt(fn func(k string, v RuntimeAfterRtFunction)) {
	re.RLock()
	for rk, rv := range re.afterRtFunctions {
		re.RUnlock()
		fn(rk, rv)
		re.RLock()
	}
	re.RUnlock()
}

func (re *RuntimeExecution) RegisterBeforeReq(key string, fn *RuntimeBeforeReqFunctions) {
	re.Lock()
	re.beforeReqFunctions = fn
	re.Unlock()
}

func (re *RuntimeExecution) RegisterAfterReq(key string, fn *RuntimeAfterReqFunctions) {
	re.Lock()
	re.afterReqFunctions = fn
	re.Unlock()
}

func (re *RuntimeExecution) RegisterEvent(fn RuntimeEventFunction) {
	re.Lock()
	re.eventFunctions = append(re.eventFunctions, fn)
	re.Unlock()
}

func (re *RuntimeExecution) CountEvent() (count int) {
	re.RLock()
	count = len(re.eventFunctions)
	re.RUnlock()
	return
}

func (re *RuntimeExecution) ScanEvent(fn func(i int, evt RuntimeEventFunction)) {
	re.RLock()
	for i, e := range re.eventFunctions {
		re.RUnlock()
		fn(i, e)
		re.RLock()
	}
	re.RUnlock()
}

func (re *RuntimeExecution) RegisterEventSessionStart(fn RuntimeEventFunction) {
	re.Lock()
	re.sessionStartFunctions = append(re.sessionStartFunctions, fn)
	re.Unlock()
}

func (re *RuntimeExecution) ScanEventSessionStart(fn func(i int, evt RuntimeEventFunction)) {
	re.RLock()
	for i, e := range re.sessionStartFunctions {
		re.RUnlock()
		fn(i, e)
		re.RLock()
	}
	re.RUnlock()
}

func (re *RuntimeExecution) CountEventSessionStart() (count int) {
	re.RLock()
	count = len(re.sessionStartFunctions)
	re.RUnlock()
	return
}

func (re *RuntimeExecution) ScanEventSessionEnd(fn func(i int, evt RuntimeEventFunction)) {
	re.RLock()
	for i, e := range re.sessionEndFunctions {
		re.RUnlock()
		fn(i, e)
		re.RLock()
	}
	re.RUnlock()
}

func (re *RuntimeExecution) RegisterEventSessionEnd(fn RuntimeEventFunction) {
	re.Lock()
	re.sessionEndFunctions = append(re.sessionEndFunctions, fn)
	re.Unlock()
}

func (re *RuntimeExecution) CountEventSessionEnd() (count int) {
	re.RLock()
	count = len(re.sessionEndFunctions)
	re.RUnlock()
	return
}

func (re *RuntimeExecution) GetBeforeReq() *RuntimeBeforeReqFunctions {
	re.RLock()
	defer re.RUnlock()
	return re.beforeReqFunctions
}

func (re *RuntimeExecution) GetAfterReq() *RuntimeAfterReqFunctions {
	re.RLock()
	defer re.RUnlock()
	return re.afterReqFunctions
}

func (re *RuntimeExecution) Merge(src *RuntimeExecution) {
	re.Lock()
	src.ScanRPC(func(k string, v RuntimeRpcFunction) {
		re.rpc[k] = v
	})
	re.Unlock()

	re.Lock()
	src.ScanBeforeRt(func(k string, v RuntimeBeforeRtFunction) {
		re.beforeRtFunctions[k] = v
	})
	re.Unlock()

	re.Lock()
	src.ScanAfterRt(func(k string, v RuntimeAfterRtFunction) {
		re.afterRtFunctions[k] = v
	})
	re.Unlock()

	re.Lock()
	mergeBeforeOrAfterFunctions(re.beforeReqFunctions, src.GetBeforeReq())
	mergeBeforeOrAfterFunctions(re.afterReqFunctions, src.GetAfterReq())
	re.Unlock()

	re.Lock()
	src.ScanEvent(func(i int, evt RuntimeEventFunction) {
		re.eventFunctions = append(re.eventFunctions, evt)
	})
	re.Unlock()

	re.Lock()
	src.ScanEventSessionStart(func(i int, evt RuntimeEventFunction) {
		re.sessionStartFunctions = append(re.sessionStartFunctions, evt)
	})
	re.Unlock()

	re.Lock()
	src.ScanEventSessionEnd(func(i int, evt RuntimeEventFunction) {
		re.sessionEndFunctions = append(re.sessionEndFunctions, evt)
	})
	re.Unlock()
}

func (re *RuntimeExecution) Trace(logger *zap.Logger, name string) *RuntimeExecution {
	re.ScanRPC(func(k string, v RuntimeRpcFunction) {
		logger.Info("Registered "+name+" runtime RPC function invocation", zap.String("id", k))
	})

	re.ScanBeforeRt(func(k string, v RuntimeBeforeRtFunction) {
		logger.Info("Registered "+name+" runtime Before function invocation", zap.String("id", k))
	})

	re.ScanAfterRt(func(k string, v RuntimeAfterRtFunction) {
		logger.Info("Registered "+name+" runtime After function invocation", zap.String("id", k))
	})

	re.RLock()
	beforeK := reflect.TypeOf(re.beforeReqFunctions).Elem()
	beforeV := reflect.ValueOf(re.beforeReqFunctions).Elem()
	for i := 0; i < beforeV.NumField(); i++ {
		if beforeV.Field(i).IsNil() {
			continue
		}
		logger.Info("Registered "+name+" runtime Before function invocation", zap.String("id", beforeK.Field(i).Name))
	}

	afterK := reflect.TypeOf(re.beforeReqFunctions).Elem()
	afterV := reflect.ValueOf(re.beforeReqFunctions).Elem()
	for i := 0; i < afterV.NumField(); i++ {
		if beforeV.Field(i).IsNil() {
			continue
		}
		logger.Info("Registered "+name+" runtime After function invocation", zap.String("id", afterK.Field(i).Name))
	}
	re.RUnlock()

	return re
}

func NewRuntimeExecution() *RuntimeExecution {
	return &RuntimeExecution{
		rpc:                make(map[string]RuntimeRpcFunction),
		beforeRtFunctions:  make(map[string]RuntimeBeforeRtFunction),
		afterRtFunctions:   make(map[string]RuntimeAfterRtFunction),
		beforeReqFunctions: &RuntimeBeforeReqFunctions{},
		afterReqFunctions:  &RuntimeAfterReqFunctions{},
	}
}

func NewRuntimeExecutionByCap(rpc, beforeRt, afterRt int) *RuntimeExecution {
	return &RuntimeExecution{
		rpc:                make(map[string]RuntimeRpcFunction, rpc),
		beforeRtFunctions:  make(map[string]RuntimeBeforeRtFunction, beforeRt),
		afterRtFunctions:   make(map[string]RuntimeAfterRtFunction, afterRt),
		beforeReqFunctions: &RuntimeBeforeReqFunctions{},
		afterReqFunctions:  &RuntimeAfterReqFunctions{},
	}
}

func RegisterRuntimeExecution(provider RuntimeProvider, re *RuntimeExecution) func(mode RuntimeExecutionMode, id string) {
	return func(mode RuntimeExecutionMode, id string) {
		switch mode {
		case RuntimeExecutionModeRPC:
			fn := func(ctx context.Context, logger *zap.Logger, r *RuntimeSameRequest, payload string) (string, error, codes.Code) {
				return provider.RegisterRPC(ctx, id, r, payload)
			}

			re.RegisterRPC(id, fn)

		case RuntimeExecutionModeBefore:
			
		case RuntimeExecutionModeAfter:
		}
	}
}

func mergeBeforeOrAfterFunctions[T *RuntimeBeforeReqFunctions | *RuntimeAfterReqFunctions](dest, src T) {
	t := reflect.ValueOf(dest).Elem()
	s := reflect.ValueOf(src).Elem()
	for i := 0; i < t.NumField(); i++ {
		if !s.Field(i).IsNil() {
			t.Field(i).Set(s.Field(i))
		}
	}
}

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
// Date: 2022-05-16 18:01:55
// LastEditors: randyma
// LastEditTime: 2022-05-16 18:02:08
// Description: Javascript 运行时实现

package linna

import (
	"context"
	"database/sql"
	"errors"
	"sort"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
)

type RuntimeJS struct {
	logger       *zap.Logger
	node         string
	nkInst       goja.Value
	jsLoggerInst goja.Value
	env          goja.Value
	vm           *goja.Runtime
	callbacks    *RuntimeJavascriptCallbacks
}

func (r *RuntimeJS) GetCallback(mode RuntimeExecutionMode, key string) string {
	switch mode {
	case RuntimeExecutionModeRPC:
		return r.callbacks.RPC[key]
	case RuntimeExecutionModeBefore:
		return r.callbacks.Before[key]
	case RuntimeExecutionModeAfter:
		return r.callbacks.After[key]
	}
	return ""
}

type jsError struct {
	StackTrace string `json:"stackTrace,omitempty"`
	custom     bool
	error
}

func (e *jsError) Error() string {
	return e.error.Error()
}

func newJsError(error error, stackTrace string, custom bool) *jsError {
	return &jsError{
		error:      error,
		custom:     custom,
		StackTrace: stackTrace,
	}
}

type RuntimeJSModule struct {
	Name    string
	Path    string
	Program *goja.Program
	Ast     *ast.Program
}

type RuntimeJSModuleCache struct {
	Names   []string
	Modules map[string]*RuntimeJSModule
}

func (mc *RuntimeJSModuleCache) Add(m *RuntimeJSModule) {
	mc.Names = append(mc.Names, m.Name)
	mc.Modules[m.Name] = m

	// Ensure modules will be listed in ascending order of names.
	sort.Strings(mc.Names)
}

// RuntimeJavascriptRequest 请求
type RuntimeJavascriptRequest struct {
	ID          string
	Headers     map[string][]string
	QueryParams map[string][]string
	UserID      string
	Username    string
	Vars        map[string]string
	Expiry      int64
	SessionID   string
	ClientIP    string
	ClientPort  string
	Lang        string
	Payloads    []interface{}
}

// RuntimeProviderJSOptions Javascript运行时
type RuntimeProviderJSOptions struct {
	Logger               *zap.Logger
	StartupLogger        *zap.Logger
	DB                   *sql.DB
	ProtojsonMarshaler   *protojson.MarshalOptions
	ProtojsonUnmarshaler *protojson.UnmarshalOptions
	Config               Configuration
	Path                 string
	Entrypoint           string
}

type RuntimeProviderJS struct {
	logger               *zap.Logger
	db                   *sql.DB
	protojsonMarshaler   *protojson.MarshalOptions
	protojsonUnmarshaler *protojson.UnmarshalOptions
	config               Configuration
	poolCh               chan *RuntimeJS
	maxCount             uint32
	currentCount         *atomic.Uint32
	newFn                func() *RuntimeJS
}

func (rp *RuntimeProviderJS) RPC(ctx context.Context, req *RuntimeJavascriptRequest) (string, error, codes.Code) {
	r, err := rp.Get(ctx)
	if err != nil {
		return "", err, codes.Internal
	}
	jsFn := r.GetCallback(RuntimeExecutionModeRPC, req.ID)
	if jsFn == "" {
		rp.Put(r)
		return "", ErrRuntimeRPCNotFound, codes.NotFound
	}

	fn, ok := goja.AssertFunction(r.vm.Get(jsFn))
	if !ok {
		rp.logger.Error("JavaScript runtime function invalid.", zap.String("key", jsFn), zap.Error(err))
		return "", errors.New("Could not run Rpc function."), codes.Internal
	}

	jsLogger, err := NewJSLogger(r.vm, r.logger, zap.String("rpc_id", req.ID))
	if err != nil {
		r.logger.Error("Could not instantiate js logger.", zap.Error(err))
		return "", errors.New("Could not run Rpc function."), codes.Internal
	}
	retValue, err, code := r.InvokeFunction(RuntimeExecutionModeRPC, fn, jsLogger, req)
	rp.Put(r)
	if err != nil {
		return "", err, code
	}

	if retValue == nil {
		return "", nil, 0
	}

	payload, ok := retValue.(string)
	if !ok {
		msg := "Runtime function returned invalid data - only allowed one return value of type string."
		rp.logger.Error(msg, zap.String("mode", RuntimeExecutionModeRPC.String()), zap.String("id", req.ID))
		return "", errors.New(msg), codes.Internal
	}

	return payload, nil, code
}

func (r *RuntimeJS) InvokeFunction(execMode RuntimeExecutionMode, fn goja.Callable, logger goja.Value, req *RuntimeJavascriptRequest) (interface{}, error, codes.Code) {
	ctx := NewRuntimeJsContext(r.vm, execMode, &RuntimeJSContextOptions{
		Node:          r.node,
		Env:           r.env,
		Headers:       req.Headers,
		QueryParams:   req.QueryParams,
		SeessionID:    req.SessionID,
		SessionExpiry: req.Expiry,
		UserID:        req.UserID,
		Username:      req.Username,
		Vars:          req.Vars,
		ClientIP:      req.ClientIP,
		ClientPort:    req.ClientPort,
		Lang:          req.Lang,
	})

	args := []goja.Value{ctx, logger, r.nkInst}
	jsArgs := make([]goja.Value, 0, len(args)+len(req.Payloads))
	jsArgs = append(jsArgs, args...)
	for _, payload := range req.Payloads {
		jsArgs = append(jsArgs, r.vm.ToValue(payload))
	}

	retVal, err, code := r.invokeFunction(execMode, req.ID, fn, jsArgs...)
	if err != nil {
		return nil, err, code
	}

	if retVal == nil {
		return nil, nil, codes.OK
	} else {
		return retVal.Export(), nil, codes.OK
	}
}

func (r *RuntimeJS) invokeFunction(execMode RuntimeExecutionMode, id string, fn goja.Callable, args ...goja.Value) (goja.Value, error, codes.Code) {
	// First argument is null because the js fn is not executed in the context of an object.
	retVal, err := fn(goja.Null(), args...)
	if err != nil {
		if exErr, ok := err.(*goja.Exception); ok {
			errMsg := exErr.Error()
			errCode := codes.Internal
			custom := false
			if errMap, ok := exErr.Value().Export().(map[string]interface{}); ok {
				// Custom exception with message and code
				if msg, ok := errMap["message"]; ok {
					if msgStr, ok := msg.(string); ok {
						errMsg = msgStr
						custom = true
					}
				}
				if code, ok := errMap["code"]; ok {
					if codeInt, ok := code.(int64); ok {
						errCode = codes.Code(codeInt)
						custom = true
					}
				}
			}

			if !custom {
				r.logger.Error("JavaScript runtime function raised an uncaught exception", zap.String("mode", execMode.String()), zap.String("id", id), zap.Error(err))
			}
			return nil, newJsError(errors.New(errMsg), exErr.String(), custom), errCode
		}
		r.logger.Error("JavaScript runtime error", zap.String("mode", execMode.String()), zap.String("id", id), zap.Error(err))
		return nil, err, codes.Internal
	}
	if retVal == nil || retVal == goja.Undefined() || retVal == goja.Null() {
		return nil, nil, codes.OK
	}

	return retVal, nil, codes.OK
}

func (rp *RuntimeProviderJS) Get(ctx context.Context) (*RuntimeJS, error) {
	select {
	case <-ctx.Done():
		// Context cancelled
		return nil, ctx.Err()
	case r := <-rp.poolCh:
		// Ideally use an available idle runtime.
		return r, nil
	default:
		// If there was no idle runtime, see if we can allocate a new one.
		if rp.currentCount.Load() >= rp.maxCount {
			// No further runtime allocation allowed.
			break
		}
		currentCount := rp.currentCount.Inc()
		if currentCount > rp.maxCount {
			// When we've incremented see if we can still allocate or a concurrent operation has already done so up to the limit.
			// The current count value may go above max count value, but we will never over-allocate runtimes.
			// This discrepancy is allowed as it avoids a full mutex locking scenario.
			break
		}
		//rp.metrics.GaugeJsRuntimes(float64(currentCount))
		return rp.newFn(), nil
	}

	// If we reach here then we were unable to find an available idle runtime, and allocation was not allowed.
	// Wait as needed.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-rp.poolCh:
		return r, nil
	}
}

func (rp *RuntimeProviderJS) Put(r *RuntimeJS) {
	select {
	case rp.poolCh <- r:
		// Runtime is successfully returned to the pool.
	default:
		// The pool is over capacity. Should never happen but guard anyway.
		// Safe to continue processing, the runtime is just discarded.
		rp.logger.Warn("JavaScript runtime pool full, discarding runtime")
	}
}

func NewRuntimeProviderJS(option *RuntimeProviderJSOptions) *RuntimeProviderJS {
	return &RuntimeProviderJS{}
}

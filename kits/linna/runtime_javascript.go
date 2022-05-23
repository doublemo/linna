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
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"github.com/doublemo/linna-common/rtapi"
	"github.com/doublemo/linna/internal/metrics"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const JavascriptEntrypointFilename = "index.js"

type RuntimeJS struct {
	logger       *zap.Logger
	node         string
	nkInst       goja.Value
	jsLoggerInst goja.Value
	env          map[string]string
	vm           *goja.Runtime
	callbacks    *RuntimeJavascriptCallbacks
}

func (r *RuntimeJS) GetCallback(mode RuntimeExecutionMode, key string) string {
	switch mode {
	case RuntimeExecutionModeRPC:
		return r.callbacks.Rpc[key]
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
	execution            *RuntimeExecution
	modules              []string
	eventFn              RuntimeEventCustomFunction
	metrics              metrics.Metrics
}

func (rp *RuntimeProviderJS) Execution() *RuntimeExecution {
	return rp.execution
}

func (rp *RuntimeProviderJS) Modules() []string {
	return rp.modules
}

func (rp *RuntimeProviderJS) RegisterRPC(ctx context.Context, id string, same *RuntimeSameRequest, payload string) (string, error, codes.Code) {
	r, err := rp.Get(ctx)
	if err != nil {
		return "", err, codes.Internal
	}
	jsFn := r.GetCallback(RuntimeExecutionModeRPC, id)
	if jsFn == "" {
		rp.Put(r)
		return "", ErrRuntimeRPCNotFound, codes.NotFound
	}

	fn, ok := goja.AssertFunction(r.vm.Get(jsFn))
	if !ok {
		rp.logger.Error("JavaScript runtime function invalid.", zap.String("key", jsFn), zap.Error(err))
		return "", errors.New("Could not run Rpc function."), codes.Internal
	}

	jsLogger, err := NewJSLogger(r.vm, r.logger, zap.String("rpc_id", id))
	if err != nil {
		r.logger.Error("Could not instantiate js logger.", zap.Error(err))
		return "", errors.New("Could not run Rpc function."), codes.Internal
	}
	retValue, err, code := r.InvokeFunction(RuntimeExecutionModeRPC, fn, jsLogger, id, same, payload)
	rp.Put(r)
	if err != nil {
		return "", err, code
	}

	if retValue == nil {
		return "", nil, 0
	}

	payload, ok = retValue.(string)
	if !ok {
		msg := "Runtime function returned invalid data - only allowed one return value of type string."
		rp.logger.Error(msg, zap.String("mode", RuntimeExecutionModeRPC.String()), zap.String("id", id))
		return "", errors.New(msg), codes.Internal
	}

	return payload, nil, code
}

func (rp *RuntimeProviderJS) RegisterBeforeRt(ctx context.Context, id string, same *RuntimeSameRequest, envelope *rtapi.Envelope) (*rtapi.Envelope, error) {
	r, err := rp.Get(ctx)
	if err != nil {
		return nil, err
	}
	jsFn := r.GetCallback(RuntimeExecutionModeBefore, id)
	if jsFn == "" {
		rp.Put(r)
		return nil, errors.New("Runtime Before function not found.")
	}

	envelopeJSON, err := rp.protojsonMarshaler.Marshal(envelope)
	if err != nil {
		rp.Put(r)
		rp.logger.Error("Could not marshall envelope to JSON", zap.Any("envelope", envelope), zap.Error(err))
		return nil, errors.New("Could not run runtime Before function.")
	}
	var envelopeMap map[string]interface{}
	if err := json.Unmarshal(envelopeJSON, &envelopeMap); err != nil {
		rp.Put(r)
		rp.logger.Error("Could not unmarshall envelope to interface{}", zap.Any("envelope_json", envelopeJSON), zap.Error(err))
		return nil, errors.New("Could not run runtime Before function.")
	}

	fn, ok := goja.AssertFunction(r.vm.Get(jsFn))
	if !ok {
		rp.logger.Error("JavaScript runtime function invalid.", zap.String("key", jsFn), zap.Error(err))
		return nil, errors.New("Could not run runtime Before function.")
	}

	jsLogger, err := NewJSLogger(r.vm, rp.logger, zap.String("api_id", strings.TrimPrefix(id, RTAPI_PREFIX_LOWERCASE)), zap.String("mode", RuntimeExecutionModeBefore.String()))
	if err != nil {
		rp.logger.Error("Could not instantiate js logger.", zap.Error(err))
		return nil, errors.New("Could not run runtime Before function.")
	}
	result, fnErr, _ := r.InvokeFunction(RuntimeExecutionModeBefore, fn, jsLogger, id, same, envelopeMap)
	rp.Put(r)

	if fnErr != nil {
		if jsErr, ok := fnErr.(*jsError); ok {
			if !jsErr.custom {
				rp.logger.Error("Runtime Before function caused an error.", zap.String("id", id), zap.Error(fnErr))
			}
		}
		return nil, fnErr
	}

	if result == nil {
		return nil, nil
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		rp.logger.Error("Could not marshal result to JSON", zap.Any("result", result), zap.Error(err))
		return nil, errors.New("Could not complete runtime Before function.")
	}

	if err = rp.protojsonUnmarshaler.Unmarshal(resultJSON, envelope); err != nil {
		rp.logger.Error("Could not unmarshal result to envelope", zap.Any("result", result), zap.Error(err))
		return nil, errors.New("Could not complete runtime Before function.")
	}

	return envelope, nil
}

func (rp *RuntimeProviderJS) RegisterAfterRt(ctx context.Context, id string, same *RuntimeSameRequest, out, in *rtapi.Envelope) error {
	r, err := rp.Get(ctx)
	if err != nil {
		return err
	}
	jsFn := r.GetCallback(RuntimeExecutionModeAfter, id)
	if jsFn == "" {
		rp.Put(r)
		return errors.New("Runtime After function not found.")
	}

	var outMap map[string]interface{}
	if out != nil {
		outJSON, err := rp.protojsonMarshaler.Marshal(out)
		if err != nil {
			rp.Put(r)
			rp.logger.Error("Could not marshall envelope to JSON", zap.Any("out", out), zap.Error(err))
			return errors.New("Could not run runtime After function.")
		}
		if err := json.Unmarshal([]byte(outJSON), &outMap); err != nil {
			rp.Put(r)
			rp.logger.Error("Could not unmarshall envelope to interface{}", zap.Any("out_json", outJSON), zap.Error(err))
			return errors.New("Could not run runtime After function.")
		}
	}

	inJSON, err := rp.protojsonMarshaler.Marshal(in)
	if err != nil {
		rp.Put(r)
		rp.logger.Error("Could not marshall envelope to JSON", zap.Any("in", in), zap.Error(err))
		return errors.New("Could not run runtime After function.")
	}
	var inMap map[string]interface{}
	if err := json.Unmarshal([]byte(inJSON), &inMap); err != nil {
		rp.Put(r)
		rp.logger.Error("Could not unmarshall envelope to interface{}", zap.Any("in_json", inJSON), zap.Error(err))
		return errors.New("Could not run runtime After function.")
	}

	fn, ok := goja.AssertFunction(r.vm.Get(jsFn))
	if !ok {
		rp.logger.Error("JavaScript runtime function invalid.", zap.String("key", jsFn), zap.Error(err))
		return errors.New("Could not run runtime After function.")
	}

	jsLogger, err := NewJSLogger(r.vm, rp.logger, zap.String("api_id", strings.TrimPrefix(id, RTAPI_PREFIX_LOWERCASE)), zap.String("mode", RuntimeExecutionModeAfter.String()))
	if err != nil {
		rp.logger.Error("Could not instantiate js logger.", zap.Error(err))
		return errors.New("Could not run runtime After function.")
	}
	_, fnErr, _ := r.InvokeFunction(RuntimeExecutionModeAfter, fn, jsLogger, id, same, outMap, inMap)
	rp.Put(r)

	if fnErr != nil {
		if jsErr, ok := fnErr.(*jsError); ok {
			if !jsErr.custom {
				rp.logger.Error("Runtime After function caused an error.", zap.String("id", id), zap.Error(fnErr))
			}
		}
		return fnErr
	}

	return nil
}

func (rp *RuntimeProviderJS) RegisterBeforeReq(ctx context.Context, id string, same *RuntimeSameRequest, req interface{}) (interface{}, error, codes.Code) {
	r, err := rp.Get(ctx)
	if err != nil {
		return nil, err, codes.Internal
	}
	jsFn := r.GetCallback(RuntimeExecutionModeBefore, id)
	if jsFn == "" {
		rp.Put(r)
		return nil, errors.New("Runtime Before function not found."), codes.NotFound
	}

	var reqMap map[string]interface{}
	var reqProto proto.Message
	if req != nil {
		// Req may be nil for requests that carry no input body.
		var ok bool
		reqProto, ok = req.(proto.Message)
		if !ok {
			rp.Put(r)
			rp.logger.Error("Could not cast request to message", zap.Any("request", req))
			return nil, errors.New("Could not run runtime Before function."), codes.Internal
		}
		reqJSON, err := rp.protojsonMarshaler.Marshal(reqProto)
		if err != nil {
			rp.Put(r)
			rp.logger.Error("Could not marshall request to JSON", zap.Any("request", reqProto), zap.Error(err))
			return nil, errors.New("Could not run runtime Before function."), codes.Internal
		}
		if err := json.Unmarshal([]byte(reqJSON), &reqMap); err != nil {
			rp.Put(r)
			rp.logger.Error("Could not unmarshall request to interface{}", zap.Any("request_json", reqJSON), zap.Error(err))
			return nil, errors.New("Could not run runtime Before function."), codes.Internal
		}
	}

	fn, ok := goja.AssertFunction(r.vm.Get(jsFn))
	if !ok {
		rp.logger.Error("JavaScript runtime function invalid.", zap.String("key", jsFn), zap.Error(err))
		return nil, errors.New("Could not run runtime Before function."), codes.Internal
	}

	jsLogger, err := NewJSLogger(r.vm, rp.logger, zap.String("api_id", strings.TrimPrefix(id, API_PREFIX_LOWERCASE)), zap.String("mode", RuntimeExecutionModeAfter.String()))
	if err != nil {
		rp.logger.Error("Could not instantiate js logger.", zap.Error(err))
		return nil, errors.New("Could not run runtime Before function."), codes.Internal
	}
	result, fnErr, code := r.InvokeFunction(RuntimeExecutionModeBefore, fn, jsLogger, id, same, reqMap)
	rp.Put(r)

	if fnErr != nil {
		if jsErr, ok := fnErr.(*jsError); ok {
			if !jsErr.custom {
				rp.logger.Error("Runtime Before function caused an error.", zap.String("id", id), zap.Error(err))
			}
		}
		return nil, fnErr, code
	}

	if result == nil || reqMap == nil {
		// There was no return value, or a return value was not expected (no input to override).
		return nil, nil, codes.OK
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		rp.logger.Error("Could not marshall result to JSON", zap.Any("result", result), zap.Error(err))
		return nil, errors.New("Could not complete runtime Before function."), codes.Internal
	}

	if err = rp.protojsonUnmarshaler.Unmarshal(resultJSON, reqProto); err != nil {
		rp.logger.Error("Could not unmarshall result to request", zap.Any("result", result), zap.Error(err))
		return nil, errors.New("Could not complete runtime Before function."), codes.Internal
	}

	return req, nil, codes.OK
}

func (rp *RuntimeProviderJS) RegisterAfterReq(ctx context.Context, id string, same *RuntimeSameRequest, res, req interface{}) error {
	r, err := rp.Get(ctx)
	if err != nil {
		return err
	}
	jsFn := r.GetCallback(RuntimeExecutionModeAfter, id)
	if jsFn == "" {
		rp.Put(r)
		return errors.New("Runtime After function not found.")
	}

	var resMap map[string]interface{}
	if res != nil {
		// Res may be nil if there is no response body.
		resProto, ok := res.(proto.Message)
		if !ok {
			rp.Put(r)
			rp.logger.Error("Could not cast response to message", zap.Any("response", res))
			return errors.New("Could not run runtime After function.")
		}
		resJSON, err := rp.protojsonMarshaler.Marshal(resProto)
		if err != nil {
			rp.Put(r)
			rp.logger.Error("Could not marshall response to JSON", zap.Any("response", resProto), zap.Error(err))
			return errors.New("Could not run runtime After function.")
		}

		if err := json.Unmarshal([]byte(resJSON), &resMap); err != nil {
			rp.Put(r)
			rp.logger.Error("Could not unmarshall response to interface{}", zap.Any("response_json", resJSON), zap.Error(err))
			return errors.New("Could not run runtime After function.")
		}
	}

	var reqMap map[string]interface{}
	if req != nil {
		// Req may be nil if there is no request body.
		reqProto, ok := req.(proto.Message)
		if !ok {
			rp.Put(r)
			rp.logger.Error("Could not cast request to message", zap.Any("request", req))
			return errors.New("Could not run runtime After function.")
		}
		reqJSON, err := rp.protojsonMarshaler.Marshal(reqProto)
		if err != nil {
			rp.Put(r)
			rp.logger.Error("Could not marshall request to JSON", zap.Any("request", reqProto), zap.Error(err))
			return errors.New("Could not run runtime After function.")
		}

		if err := json.Unmarshal([]byte(reqJSON), &reqMap); err != nil {
			rp.Put(r)
			rp.logger.Error("Could not unmarshall request to interface{}", zap.Any("request_json", reqJSON), zap.Error(err))
			return errors.New("Could not run runtime After function.")
		}
	}

	fn, ok := goja.AssertFunction(r.vm.Get(jsFn))
	if !ok {
		rp.logger.Error("JavaScript runtime function invalid.", zap.String("key", jsFn), zap.Error(err))
		return errors.New("Could not run runtime After function.")
	}

	jsLogger, err := NewJSLogger(r.vm, r.logger, zap.String("api_id", strings.TrimPrefix(id, API_PREFIX_LOWERCASE)), zap.String("mode", RuntimeExecutionModeAfter.String()))
	if err != nil {
		rp.logger.Error("Could not instantiate js logger.", zap.Error(err))
		return errors.New("Could not run runtime After function.")
	}
	_, fnErr, _ := r.InvokeFunction(RuntimeExecutionModeAfter, fn, jsLogger, id, same, resMap, reqMap)
	rp.Put(r)

	if fnErr != nil {
		if jsErr, ok := fnErr.(*jsError); ok {
			if !jsErr.custom {
				rp.logger.Error("JavaScript runtime After function caused an error.", zap.String("id", id), zap.Error(fnErr))
			}
		}
		return fnErr
	}

	return nil
}

func (r *RuntimeJS) InvokeFunction(execMode RuntimeExecutionMode, fn goja.Callable, logger goja.Value, id string, same *RuntimeSameRequest, payloads ...interface{}) (interface{}, error, codes.Code) {
	ctx := NewRuntimeJsContext(r.vm, execMode, NewRuntimeContextConfigurationFromSameRequest(r.node, r.env, same))

	args := []goja.Value{ctx, logger, r.nkInst}
	jsArgs := make([]goja.Value, 0, len(args)+len(payloads))
	jsArgs = append(jsArgs, args...)
	for _, payload := range payloads {
		jsArgs = append(jsArgs, r.vm.ToValue(payload))
	}

	retVal, err, code := r.invokeFunction(execMode, id, fn, jsArgs...)
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
		rp.metrics.GaugeJsRuntimes(float64(currentCount))
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

func NewRuntimeProviderJS(c *RuntimeProviderConfiguration) (*RuntimeProviderJS, error) {
	logger := c.Logger
	startupLogger := c.StartupLogger
	config := c.Config
	runtimeConfig := config.Runtime
	startupLogger.Info("Initialising JavaScript runtime provider", zap.String("path", runtimeConfig.Path), zap.String("entrypoint", runtimeConfig.JsEntrypoint))

	modCache, err := cacheJavascriptModules(startupLogger, runtimeConfig.Path, runtimeConfig.JsEntrypoint)
	if err != nil {
		startupLogger.Fatal("Failed to load JavaScript files", zap.Error(err))
	}

	localCache := NewRuntimeJavascriptLocalCache()
	runtimeProviderJS := &RuntimeProviderJS{
		logger:               c.Logger,
		db:                   c.DB,
		protojsonMarshaler:   c.ProtojsonMarshaler,
		protojsonUnmarshaler: c.ProtojsonUnmarshaler,
		config:               config,
		poolCh:               make(chan *RuntimeJS, runtimeConfig.JsMaxCount),
		maxCount:             uint32(runtimeConfig.JsMaxCount),
		currentCount:         atomic.NewUint32(uint32(runtimeConfig.JsMinCount)),
		execution:            NewRuntimeExecution(),
		modules:              make([]string, 0),
		eventFn:              c.EventFn.eventFunction,
		metrics:              c.Metrics,
	}

	callbacks, err := evalRuntimeModules(runtimeProviderJS, modCache, localCache, RegisterRuntimeExecution(runtimeProviderJS, runtimeProviderJS.execution), false)
	if err != nil {
		logger.Error("Failed to eval JavaScript modules.", zap.Error(err))
		return nil, err
	}

	runtimeProviderJS.newFn = func() *RuntimeJS {
		runtime := goja.New()
		runtime.RunProgram(modCache.Modules[modCache.Names[0]].Program)
		freezeGlobalObject(runtimeConfig, runtime)

		jsLoggerInst, err := NewJSLogger(runtime, logger)
		if err != nil {
			logger.Fatal("Failed to initialize JavaScript runtime", zap.Error(err))
		}

		nam := NewRuntimeJavascriptLinnaModule(&RuntimeJavascriptLinnaModuleConfiguration{
			Logger:               logger,
			DB:                   c.DB,
			ProtojsonMarshaler:   c.ProtojsonMarshaler,
			ProtojsonUnmarshaler: c.ProtojsonUnmarshaler,
			Config:               config,
			Node:                 config.Endpoint.ID,
			EventFn:              c.EventFn.eventFunction,
			Metrics:              c.Metrics,
		})
		na := runtime.ToValue(nam.Constructor(runtime))
		nkInst, err := runtime.New(na)
		if err != nil {
			logger.Fatal("Failed to initialize JavaScript runtime", zap.Error(err))
		}

		return &RuntimeJS{
			logger:       logger,
			jsLoggerInst: jsLoggerInst,
			nkInst:       nkInst,
			node:         config.Endpoint.ID,
			vm:           runtime,
			env:          runtimeConfig.Environment,
			callbacks:    callbacks,
		}
	}

	startupLogger.Info("JavaScript runtime modules loaded")
	startupLogger.Info("Allocating minimum JavaScript runtime pool", zap.Int("count", runtimeConfig.JsMinCount))
	if len(modCache.Names) > 0 {
		// Only if there are runtime modules to load.
		for i := 0; i < runtimeConfig.JsMinCount; i++ {
			runtimeProviderJS.poolCh <- runtimeProviderJS.newFn()
		}
		runtimeProviderJS.metrics.GaugeJsRuntimes(float64(runtimeConfig.JsMinCount))
	}
	startupLogger.Info("Allocated minimum JavaScript runtime pool")
	runtimeProviderJS.modules = modCache.Names
	return runtimeProviderJS, nil
}

func CheckRuntimeProviderJavascript(logger *zap.Logger, config Configuration) error {
	modCache, err := cacheJavascriptModules(logger, config.Runtime.Path, config.Runtime.JsEntrypoint)
	if err != nil {
		return err
	}
	rp := &RuntimeProviderJS{
		logger: logger,
		config: config,
	}
	_, err = evalRuntimeModules(rp, modCache, nil, func(RuntimeExecutionMode, string) {}, true)
	if err != nil {
		logger.Error("Failed to load JavaScript module.", zap.Error(err))
	}
	return err
}

func cacheJavascriptModules(logger *zap.Logger, path, entrypoint string) (*RuntimeJSModuleCache, error) {
	moduleCache := &RuntimeJSModuleCache{
		Names:   make([]string, 0),
		Modules: make(map[string]*RuntimeJSModule),
	}

	var absEntrypoint string
	if entrypoint == "" {
		// If entrypoint is not set, look for index.js file in path; skip if not found.
		absEntrypoint = filepath.Join(path, JavascriptEntrypointFilename)
		if _, err := os.Stat(absEntrypoint); os.IsNotExist(err) {
			return moduleCache, nil
		}
	} else {
		absEntrypoint = filepath.Join(path, entrypoint)
	}

	var content []byte
	var err error
	if content, err = ioutil.ReadFile(absEntrypoint); err != nil {
		logger.Error("Could not read JavaScript module", zap.String("entrypoint", absEntrypoint), zap.Error(err))
		return nil, err
	}

	var modName string
	if entrypoint == "" {
		modName = filepath.Base(JavascriptEntrypointFilename)
	} else {
		modName = filepath.Base(entrypoint)
	}
	ast, _ := goja.Parse(modName, string(content))
	prg, err := goja.Compile(modName, string(content), true)
	if err != nil {
		logger.Error("Could not compile JavaScript module", zap.String("module", modName), zap.Error(err))
		return nil, err
	}

	moduleCache.Add(&RuntimeJSModule{
		Name:    modName,
		Path:    absEntrypoint,
		Program: prg,
		Ast:     ast,
	})

	return moduleCache, nil
}

func evalRuntimeModules(rp *RuntimeProviderJS, modCache *RuntimeJSModuleCache, localCache *RuntimeJavascriptLocalCache, announceCallbackFn func(RuntimeExecutionMode, string), dryRun bool) (*RuntimeJavascriptCallbacks, error) {
	logger := rp.logger

	r := goja.New()

	callbacks := &RuntimeJavascriptCallbacks{
		Rpc:    make(map[string]string),
		Before: make(map[string]string),
		After:  make(map[string]string),
	}

	// TODO: refactor modCache
	if len(modCache.Names) == 0 {
		// There are no JS runtime modules to run.
		return callbacks, nil
	}
	modName := modCache.Names[0]

	initializer := NewRuntimeJavascriptInitModule(logger, modCache.Modules[modName].Ast, callbacks, announceCallbackFn)
	initializerValue := r.ToValue(initializer.Constructor(r))
	initializerInst, err := r.New(initializerValue)
	if err != nil {
		return nil, err
	}

	jsLoggerInst, err := NewJSLogger(r, logger)
	if err != nil {
		return nil, err
	}

	nam := NewRuntimeJavascriptLinnaModule(&RuntimeJavascriptLinnaModuleConfiguration{
		Logger:               logger,
		DB:                   rp.db,
		ProtojsonMarshaler:   rp.protojsonMarshaler,
		ProtojsonUnmarshaler: rp.protojsonUnmarshaler,
		Config:               rp.config,
		Node:                 rp.config.Endpoint.ID,
		EventFn:              rp.eventFn,
		Metrics:              rp.metrics,
	})
	na := r.ToValue(nam.Constructor(r))
	naInst, err := r.New(na)
	if err != nil {
		return nil, err
	}

	_, err = r.RunProgram(modCache.Modules[modName].Program)
	if err != nil {
		return nil, err
	}

	initMod := r.Get("InitModule")
	initModFn, ok := goja.AssertFunction(initMod)
	if !ok {
		logger.Error("InitModule function not found. Function must be defined at top level.", zap.String("module", modName))
		return nil, errors.New(INIT_MODULE_FN_NAME + " function not found.")
	}

	if dryRun {
		// Parse JavaScript code for syntax errors but do not execute the InitModule function.
		return nil, nil
	}

	// Execute init module function
	ctx := NewRuntimeJsInitContext(r, rp.config.Endpoint.ID, rp.config.Runtime.Environment)
	_, err = initModFn(goja.Null(), ctx, jsLoggerInst, naInst, initializerInst)
	if err != nil {
		if exErr, ok := err.(*goja.Exception); ok {
			return nil, errors.New(exErr.String())
		}
		return nil, err
	}

	return initializer.Callbacks, nil
}

// Equivalent to calling freeze on the JavaScript global object making it immutable
// https://github.com/dop251/goja/issues/362
func freezeGlobalObject(config RuntimeConfiguration, r *goja.Runtime) {
	if !config.JsReadOnlyGlobals {
		return
	}
	r.RunString(`
for (const k of Reflect.ownKeys(globalThis)) {
    const v = globalThis[k];
    if (v) {
        Object.freeze(v);
        v.prototype && Object.freeze(v.prototype);
        v.__proto__ && Object.freeze(v.__proto__);
    }
}
`)
}

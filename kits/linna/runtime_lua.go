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
// Date: 2022-05-18 15:40:07
// LastEditors: randyma
// LastEditTime: 2022-05-18 15:40:20
// Description: Lua运行时

package linna

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	lua "github.com/doublemo/linna/cores/gopher-lua"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
)

const LTSentinel = lua.LValueType(-1)

type LSentinelType struct {
	lua.LNilType
}

func (s *LSentinelType) String() string       { return "" }
func (s *LSentinelType) Type() lua.LValueType { return LTSentinel }

var LSentinel = lua.LValue(&LSentinelType{})

type RuntimeLuaCallbacks struct {
	RPC    map[string]*lua.LFunction
	Before map[string]*lua.LFunction
	After  map[string]*lua.LFunction
}

type RuntimeLuaModule struct {
	Name    string
	Path    string
	Content []byte
}

type RuntimeLuaModuleCache struct {
	Names   []string
	Modules map[string]*RuntimeLuaModule
}

func (mc *RuntimeLuaModuleCache) Add(m *RuntimeLuaModule) {
	mc.Names = append(mc.Names, m.Name)
	mc.Modules[m.Name] = m

	// Ensure modules will be listed in ascending order of names.
	sort.Strings(mc.Names)
}

type RuntimeProviderLua struct {
	logger               *zap.Logger
	db                   *sql.DB
	protojsonMarshaler   *protojson.MarshalOptions
	protojsonUnmarshaler *protojson.UnmarshalOptions
	config               Configuration
	stdLibs              map[string]lua.LGFunction

	once         *sync.Once
	poolCh       chan *RuntimeLua
	maxCount     uint32
	currentCount *atomic.Uint32
	newFn        func() *RuntimeLua

	statsCtx  context.Context
	execution *RuntimeExecution
	modules   []string
}

func NewRuntimeProviderLua(c *RuntimeProviderConfiguration) (*RuntimeProviderLua, error) {
	logger := c.Logger
	startupLogger := c.StartupLogger
	config := c.Config
	runtimeConfig := config.Runtime
	startupLogger.Info("Initialising Lua runtime provider", zap.String("path", runtimeConfig.Path))

	// Load Lua modules into memory by reading the file contents. No evaluation/execution at this stage.
	moduleCache, modulePaths, stdLibs, err := openLuaModules(startupLogger, runtimeConfig.Path, c.Paths)
	if err != nil {
		// Errors already logged in the function call above.
		return nil, err
	}

	once := &sync.Once{}
	localCache := NewRuntimeLuaLocalCache()
	var sharedReg *lua.LTable
	var sharedGlobals *lua.LTable
	runtimeProviderLua := &RuntimeProviderLua{
		logger:               c.Logger,
		db:                   c.DB,
		protojsonMarshaler:   c.ProtojsonMarshaler,
		protojsonUnmarshaler: c.ProtojsonUnmarshaler,
		config:               c.Config,
		stdLibs:              stdLibs,

		once:     once,
		poolCh:   make(chan *RuntimeLua, runtimeConfig.LuaMaxCount),
		maxCount: uint32(runtimeConfig.LuaMaxCount),
		// Set the current count assuming we'll warm up the pool in a moment.
		currentCount: atomic.NewUint32(uint32(runtimeConfig.LuaMinCount)),

		statsCtx:  context.Background(),
		execution: NewRuntimeExecution(),
		modules:   modulePaths,
	}

	na := &RuntimeLuaLinnaModuleConfiguration{
		Logger:               c.Logger,
		DB:                   c.DB,
		ProtojsonMarshaler:   c.ProtojsonMarshaler,
		ProtojsonUnmarshaler: c.ProtojsonUnmarshaler,
		Config:               c.Config,
		EventFn:              c.EventFn.eventFunction,
		Once:                 once,
		LocalCache:           localCache,
	}

	na.AnnounceCallbackFn = RegisterRuntimeExecution(runtimeProviderLua, runtimeProviderLua.execution)
	r, err := newRuntimeLuaVM(moduleCache, stdLibs, na)
	if err != nil {
		return nil, err
	}

	if runtimeConfig.LuaReadOnlyGlobals {
		// Capture shared globals from reference state.
		sharedGlobals = r.vm.NewTable()
		sharedGlobals.RawSetString("__index", r.vm.Get(lua.GlobalsIndex))
		sharedGlobals.SetReadOnlyRecursive()
		sharedReg = r.vm.NewTable()
		sharedReg.RawSetString("__index", r.vm.Get(lua.RegistryIndex))
		sharedReg.SetReadOnlyRecursive()
		callbacksGlobals := r.callbacks

		r.Stop()
		runtimeProviderLua.newFn = func() *RuntimeLua {
			vm := lua.NewState(lua.Options{
				CallStackSize:       runtimeConfig.LuaCallStackSize,
				RegistrySize:        runtimeConfig.LuaRegistrySize,
				SkipOpenLibs:        true,
				IncludeGoStackTrace: true,
			})
			vm.SetContext(context.Background())
			vm.Get(lua.GlobalsIndex).(*lua.LTable).Metatable = sharedGlobals

			stateRegistry := vm.Get(lua.RegistryIndex).(*lua.LTable)
			stateRegistry.Metatable = sharedReg

			loadedTable := vm.NewTable()
			loadedTable.Metatable = vm.GetField(stateRegistry, "_LOADED")
			vm.SetField(stateRegistry, "_LOADED", loadedTable)

			r := &RuntimeLua{
				logger:    c.Logger,
				node:      config.Endpoint.ID,
				vm:        vm,
				env:       runtimeConfig.Environment,
				callbacks: callbacksGlobals,
			}
			return r
		}
	} else {
		r.Stop()
		runtimeProviderLua.newFn = func() *RuntimeLua {
			na.AnnounceCallbackFn = nil
			r, err := newRuntimeLuaVM(moduleCache, stdLibs, na)
			if err != nil {
				logger.Fatal("Failed to initialize Lua runtime", zap.Error(err))
			}
			return r
		}
	}

	startupLogger.Info("Lua runtime modules loaded")

	// Warm up the pool.
	startupLogger.Info("Allocating minimum Lua runtime pool", zap.Int("count", runtimeConfig.LuaMinCount))
	if len(moduleCache.Names) > 0 {
		// Only if there are runtime modules to load.
		for i := 0; i < runtimeConfig.LuaMinCount; i++ {
			runtimeProviderLua.poolCh <- runtimeProviderLua.newFn()
		}
		//runtimeProviderLua.metrics.GaugeLuaRuntimes(float64(config.GetRuntime().GetLuaMinCount()))
	}
	startupLogger.Info("Allocated minimum Lua runtime pool")
	return runtimeProviderLua, nil
}

func (rp *RuntimeProviderLua) Execution() *RuntimeExecution {
	return rp.execution
}

func (rp *RuntimeProviderLua) Modules() []string {
	return rp.modules
}

func (rp *RuntimeProviderLua) Get(ctx context.Context) (*RuntimeLua, error) {
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
			// No further runtime allocations allowed.
			break
		}
		currentCount := rp.currentCount.Inc()
		if currentCount > rp.maxCount {
			// When we've incremented see if we can still allocate or a concurrent operation has already done so up to the limit.
			// The current count value may go above max count value, but we will never over-allocate runtimes.
			// This discrepancy is allowed as it avoids a full mutex locking scenario.
			break
		}
		//rp.metrics.GaugeLuaRuntimes(float64(currentCount))
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

func (rp *RuntimeProviderLua) Put(r *RuntimeLua) {
	select {
	case rp.poolCh <- r:
		// Runtime is successfully returned to the pool.
	default:
		// The pool is over capacity. Should never happen but guard anyway.
		// Safe to continue processing, the runtime is just discarded.
		rp.logger.Warn("Lua runtime pool full, discarding Lua runtime")
	}
}

type RuntimeLua struct {
	logger    *zap.Logger
	node      string
	vm        *lua.LState
	env       map[string]string
	callbacks *RuntimeLuaCallbacks
}

func CheckRuntimeProviderLua(logger *zap.Logger, config Configuration, paths []string) error {
	// Load Lua modules into memory by reading the file contents. No evaluation/execution at this stage.
	moduleCache, _, stdLibs, err := openLuaModules(logger, config.Runtime.Path, paths)
	if err != nil {
		// Errors already logged in the function call above.
		return err
	}

	// Evaluate (but do not execute) available Lua modules.
	err = checkRuntimeLuaVM(logger, config, stdLibs, moduleCache)
	if err != nil {
		// Errors already logged in the function call above.
		return err
	}

	return nil
}

func openLuaModules(logger *zap.Logger, rootPath string, paths []string) (*RuntimeLuaModuleCache, []string, map[string]lua.LGFunction, error) {
	moduleCache := &RuntimeLuaModuleCache{
		Names:   make([]string, 0),
		Modules: make(map[string]*RuntimeLuaModule, 0),
	}
	modulePaths := make([]string, 0)

	// Override before Package library is invoked.
	lua.LuaLDir = rootPath
	lua.LuaPathDefault = lua.LuaLDir + string(os.PathSeparator) + "?.lua;" + lua.LuaLDir + string(os.PathSeparator) + "?" + string(os.PathSeparator) + "init.lua"
	if err := os.Setenv(lua.LuaPath, lua.LuaPathDefault); err != nil {
		logger.Error("Could not set Lua module path", zap.Error(err))
		return nil, nil, nil, err
	}

	for _, path := range paths {
		if strings.ToLower(filepath.Ext(path)) != ".lua" {
			continue
		}

		// Load the file contents into memory.
		var content []byte
		var err error
		if content, err = ioutil.ReadFile(path); err != nil {
			logger.Error("Could not read Lua module", zap.String("path", path), zap.Error(err))
			return nil, nil, nil, err
		}

		relPath, _ := filepath.Rel(rootPath, path)
		name := strings.TrimSuffix(relPath, filepath.Ext(relPath))
		// Make paths Lua friendly.
		name = strings.Replace(name, string(os.PathSeparator), ".", -1)

		moduleCache.Add(&RuntimeLuaModule{
			Name:    name,
			Path:    path,
			Content: content,
		})
		modulePaths = append(modulePaths, relPath)
	}

	stdLibs := map[string]lua.LGFunction{
		lua.LoadLibName:   OpenPackage(moduleCache),
		lua.BaseLibName:   lua.OpenBase,
		lua.TabLibName:    lua.OpenTable,
		lua.OsLibName:     OpenOs,
		lua.StringLibName: lua.OpenString,
		lua.MathLibName:   lua.OpenMath,
		Bit32LibName:      OpenBit32,
	}

	return moduleCache, modulePaths, stdLibs, nil
}

func (rp *RuntimeProviderLua) Rpc(ctx context.Context, id string, c *RuntimeSameRequest, payload string) (string, error, codes.Code) {
	r, err := rp.Get(ctx)
	if err != nil {
		return "", err, codes.Internal
	}
	lf := r.GetCallback(RuntimeExecutionModeRPC, id)
	if lf == nil {
		rp.Put(r)
		return "", ErrRuntimeRPCNotFound, codes.NotFound
	}

	// Set context value used for logging
	vmCtx := context.WithValue(ctx, ctxLoggerFields{}, map[string]string{"rpc_id": id})
	r.vm.SetContext(vmCtx)
	result, fnErr, code, isCustomErr := r.InvokeFunction(RuntimeExecutionModeRPC, lf, c, payload)
	r.vm.SetContext(context.Background())
	rp.Put(r)

	if fnErr != nil {
		if !isCustomErr {
			// Errors triggered with `error({msg, code})` could only have come directly from custom runtime code.
			// Assume they've been fully handled (logged etc) before that error is invoked.
			rp.logger.Error("Runtime RPC function caused an error", zap.String("id", id), zap.Error(fnErr))
		}

		if code <= 0 || code >= 17 {
			// If error is present but code is invalid then default to 13 (Internal) as the error code.
			code = 13
		}

		return "", clearFnError(fnErr, rp, lf), code
	}

	if result == nil {
		return "", nil, 0
	}

	payload, ok := result.(string)
	if !ok {
		rp.logger.Warn("Lua runtime function returned invalid data", zap.Any("result", result))
		return "", errors.New("Runtime function returned invalid data - only allowed one return value of type String/Byte."), codes.Internal
	}
	return payload, nil, 0
}

func (r *RuntimeLua) loadModules(moduleCache *RuntimeLuaModuleCache) error {
	// `DoFile(..)` only parses and evaluates modules. Calling it multiple times, will load and eval the file multiple times.
	// So to make sure that we only load and evaluate modules once, regardless of whether there is dependency between files, we load them all into `preload`.
	// This is to make sure that modules are only loaded and evaluated once as `doFile()` does not (always) update _LOADED table.
	// Bear in mind two separate thoughts around the script runtime design choice:
	//
	// 1) This is only a problem if one module is dependent on another module.
	// This means that the global functions are evaluated once at system startup and then later on when the module is required through `require`.
	// We circumvent this by checking the _LOADED table to check if `require` had evaluated the module and avoiding double-eval.
	//
	// 2) Second item is that modules must be pre-loaded into the state for callback-func eval to work properly (in case of HTTP/RPC/etc invokes)
	// So we need to always load the modules into the system via `preload` so that they are always available in the LState.
	// We can't rely on `require` to have seen the module in case there is no dependency between the modules.

	//for _, mod := range r.modules {
	//	relPath, _ := filepath.Rel(r.luaPath, mod)
	//	moduleName := strings.TrimSuffix(relPath, filepath.Ext(relPath))
	//
	//	// check to see if this module was loaded by `require` before executing it
	//	loaded := l.GetField(l.Get(lua.RegistryIndex), "_LOADED")
	//	lv := l.GetField(loaded, moduleName)
	//	if lua.LVAsBool(lv) {
	//		// Already evaluated module via `require(..)`
	//		continue
	//	}
	//
	//	if err = l.DoFile(mod); err != nil {
	//		failedModules++
	//		r.logger.Error("Failed to evaluate module - skipping", zap.String("path", mod), zap.Error(err))
	//	}
	//}

	preload := r.vm.GetField(r.vm.GetField(r.vm.Get(lua.EnvironIndex), "package"), "preload")
	fns := make(map[string]*lua.LFunction)
	for _, name := range moduleCache.Names {
		module, ok := moduleCache.Modules[name]
		if !ok {
			r.logger.Fatal("Failed to find named module in cache", zap.String("name", name))
		}
		f, err := r.vm.Load(bytes.NewReader(module.Content), module.Path)
		if err != nil {
			r.logger.Error("Could not load module", zap.String("name", module.Path), zap.Error(err))
			return err
		}
		r.vm.SetField(preload, module.Name, f)
		fns[module.Name] = f
	}

	for _, name := range moduleCache.Names {
		fn, ok := fns[name]
		if !ok {
			r.logger.Fatal("Failed to find named module in prepared functions", zap.String("name", name))
		}
		loaded := r.vm.GetField(r.vm.Get(lua.RegistryIndex), "_LOADED")
		lv := r.vm.GetField(loaded, name)
		if lua.LVAsBool(lv) {
			// Already evaluated module via `require(..)`
			continue
		}

		r.vm.Push(fn)
		fnErr := r.vm.PCall(0, -1, nil)
		if fnErr != nil {
			r.logger.Error("Could not complete runtime invocation", zap.Error(fnErr))
			return fnErr
		}
	}

	return nil
}

func (r *RuntimeLua) GetCallback(e RuntimeExecutionMode, key string) *lua.LFunction {
	switch e {
	case RuntimeExecutionModeRPC:
		return r.callbacks.RPC[key]
	case RuntimeExecutionModeBefore:
		return r.callbacks.Before[key]
	case RuntimeExecutionModeAfter:
		return r.callbacks.After[key]
	}

	return nil
}

func (r *RuntimeLua) InvokeFunction(execMode RuntimeExecutionMode, fn *lua.LFunction, same *RuntimeSameRequest, payloads ...interface{}) (interface{}, error, codes.Code, bool) {
	ctx := NewRuntimeLuaContext(r.vm, execMode, NewRuntimeContextConfigurationFromSameRequest(r.node, r.env, same))
	lv := make([]lua.LValue, 0, len(payloads))
	for _, payload := range payloads {
		lv = append(lv, RuntimeLuaConvertValue(r.vm, payload))
	}

	retValue, err, code, isCustomErr := r.invokeFunction(r.vm, fn, ctx, lv...)
	if err != nil {
		return nil, err, code, isCustomErr
	}

	if retValue == nil || retValue == lua.LNil {
		return nil, nil, 0, false
	}

	return RuntimeLuaConvertLuaValue(retValue), nil, 0, false
}

func (r *RuntimeLua) invokeFunction(l *lua.LState, fn *lua.LFunction, ctx *lua.LTable, payloads ...lua.LValue) (lua.LValue, error, codes.Code, bool) {
	l.Push(LSentinel)
	l.Push(fn)

	nargs := 1
	l.Push(ctx)

	for _, payload := range payloads {
		l.Push(payload)
		nargs++
	}

	err := l.PCall(nargs, lua.MultRet, nil)
	if err != nil {
		// Unwind the stack up to and including our sentinel value, effectively discarding any other returned parameters.
		for {
			v := l.Get(-1)
			l.Pop(1)
			if v.Type() == LTSentinel {
				break
			}
		}

		if apiError, ok := err.(*lua.ApiError); ok && apiError.Object.Type() == lua.LTTable {
			t := apiError.Object.(*lua.LTable)
			switch t.Len() {
			case 0:
				return nil, err, codes.Internal, false
			case 1:
				apiError.Object = t.RawGetInt(1)
				return nil, err, codes.Internal, false
			default:
				// Ignore everything beyond the first 2 params, if there are more.
				apiError.Object = t.RawGetInt(1)
				code := codes.Internal
				if c := t.RawGetInt(2); c.Type() == lua.LTNumber {
					code = codes.Code(c.(lua.LNumber))
				}
				return nil, err, code, true
			}
		}

		return nil, err, codes.Internal, false
	}

	retValue := l.Get(-1)
	l.Pop(1)
	if retValue.Type() == LTSentinel {
		return nil, nil, 0, false
	}

	// Unwind the stack up to and including our sentinel value, effectively discarding any other returned parameters.
	for {
		v := l.Get(-1)
		l.Pop(1)
		if v.Type() == LTSentinel {
			break
		}
	}

	return retValue, nil, 0, false
}

func (r *RuntimeLua) Stop() {
	// Not necessarily required as it only does OS temp files cleanup, which we don't expose in the runtime.
	r.vm.Close()
}

func clearFnError(fnErr error, rp *RuntimeProviderLua, lf *lua.LFunction) error {
	if apiErr, ok := fnErr.(*lua.ApiError); ok && !rp.config.Runtime.LuaApiStacktrace {
		msg := apiErr.Object.String()
		if strings.HasPrefix(msg, lf.Proto.SourceName) {
			msg = msg[len(lf.Proto.SourceName):]
			msgParts := strings.SplitN(msg, ": ", 2)
			if len(msgParts) == 2 {
				msg = msgParts[1]
			} else {
				msg = msgParts[0]
			}
		}
		return errors.New(msg)
	}
	return fnErr
}

func checkRuntimeLuaVM(logger *zap.Logger, config Configuration, stdLibs map[string]lua.LGFunction, moduleCache *RuntimeLuaModuleCache) error {
	vm := lua.NewState(lua.Options{
		CallStackSize:       config.Runtime.LuaCallStackSize,
		RegistrySize:        config.Runtime.LuaRegistrySize,
		SkipOpenLibs:        true,
		IncludeGoStackTrace: true,
	})
	vm.SetContext(context.Background())
	for name, lib := range stdLibs {
		vm.Push(vm.NewFunction(lib))
		vm.Push(lua.LString(name))
		vm.Call(1, 0)
	}
	na := NewRuntimeLuaLinnaModule(&RuntimeLuaLinnaModuleConfiguration{
		Config: config,
	})
	vm.PreloadModule("linna", na.Loader)

	preload := vm.GetField(vm.GetField(vm.Get(lua.EnvironIndex), "package"), "preload")
	for _, name := range moduleCache.Names {
		module, ok := moduleCache.Modules[name]
		if !ok {
			logger.Fatal("Failed to find named module in cache", zap.String("name", name))
		}

		f, err := vm.Load(bytes.NewReader(module.Content), module.Path)
		if err != nil {
			logger.Error("Could not load module", zap.String("name", module.Path), zap.Error(err))
			return err
		}
		vm.SetField(preload, module.Name, f)
	}

	return nil
}

func newRuntimeLuaVM(moduleCache *RuntimeLuaModuleCache, stdLibs map[string]lua.LGFunction, c *RuntimeLuaLinnaModuleConfiguration) (*RuntimeLua, error) {
	runtimeConfig := c.Config.Runtime
	vm := lua.NewState(lua.Options{
		CallStackSize:       runtimeConfig.LuaCallStackSize,
		RegistrySize:        runtimeConfig.LuaRegistrySize,
		SkipOpenLibs:        true,
		IncludeGoStackTrace: true,
	})
	vm.SetContext(context.Background())
	for name, lib := range stdLibs {
		vm.Push(vm.NewFunction(lib))
		vm.Push(lua.LString(name))
		vm.Call(1, 0)
	}
	callbacks := &RuntimeLuaCallbacks{
		RPC:    make(map[string]*lua.LFunction),
		Before: make(map[string]*lua.LFunction),
		After:  make(map[string]*lua.LFunction),
	}

	na := NewRuntimeLuaLinnaModule(c)
	na.registerCallbackFn = func(e RuntimeExecutionMode, key string, fn *lua.LFunction) {
		switch e {
		case RuntimeExecutionModeRPC:
			callbacks.RPC[key] = fn
		case RuntimeExecutionModeBefore:
			callbacks.Before[key] = fn
		case RuntimeExecutionModeAfter:
			callbacks.After[key] = fn
		}
	}

	vm.PreloadModule("linna", na.Loader)
	r := &RuntimeLua{
		logger:    c.Logger,
		node:      c.Config.Endpoint.ID,
		vm:        vm,
		env:       runtimeConfig.Environment,
		callbacks: callbacks,
	}

	return r, r.loadModules(moduleCache)
}

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
// Date: 2022-05-16 18:05:24
// LastEditors: randyma
// LastEditTime: 2022-05-16 18:05:32
// Description: Javascript 运行时

package linna

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"go.uber.org/zap"
)

const INIT_MODULE_FN_NAME = "InitModule"

var inlinedFunctionError = errors.New("function literal found: javascript functions cannot be inlined")

// RuntimeJavascriptCallbacks JS回调
type RuntimeJavascriptCallbacks struct {
	Rpc    map[string]string
	Before map[string]string
	After  map[string]string
}

type RuntimeJavascriptInitModule struct {
	Logger             *zap.Logger
	Callbacks          *RuntimeJavascriptCallbacks
	announceCallbackFn func(RuntimeExecutionMode, string)
	ast                *ast.Program
}

// NewRuntimeJavascriptInitModule Javascript运行时初始化
func NewRuntimeJavascriptInitModule(logger *zap.Logger, ast *ast.Program, callbacks *RuntimeJavascriptCallbacks, announceCallbackFn func(RuntimeExecutionMode, string)) *RuntimeJavascriptInitModule {
	return &RuntimeJavascriptInitModule{
		Logger:             logger,
		announceCallbackFn: announceCallbackFn,
		Callbacks:          callbacks,
		ast:                ast,
	}
}

func (im *RuntimeJavascriptInitModule) mappings(r *goja.Runtime) map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value{
		"registerRpc":      im.registerRpc(r),
		"registerRtBefore": im.registerRtBefore(r),
		"registerRtAfter":  im.registerRtAfter(r),
	}
}

func (im *RuntimeJavascriptInitModule) Constructor(r *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for key, fn := range im.mappings(r) {
			call.This.Set(key, fn)
		}

		return nil
	}
}

func (im *RuntimeJavascriptInitModule) registerRpc(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		fName := f.Argument(0)
		if goja.IsNull(fName) || goja.IsUndefined(fName) {
			panic(r.NewTypeError("expects a non empty string"))
		}
		key, ok := fName.Export().(string)
		if !ok {
			panic(r.NewTypeError("expects a non empty string"))
		}
		if key == "" {
			panic(r.NewTypeError("expects a non empty string"))
		}

		fn := f.Argument(1)
		_, ok = goja.AssertFunction(fn)
		if !ok {
			panic(r.NewTypeError("expects a function"))
		}

		fnKey, err := im.extractRpcFn(r, key)
		if err != nil {
			panic(r.NewGoError(err))
		}

		lKey := strings.ToLower(key)
		im.registerCallbackFn(RuntimeExecutionModeRPC, lKey, fnKey)
		im.announceCallbackFn(RuntimeExecutionModeRPC, lKey)

		return goja.Undefined()
	}
}

func (im *RuntimeJavascriptInitModule) extractRpcFn(r *goja.Runtime, rpcFnName string) (string, error) {
	bs, initFnVarName, err := im.getInitModuleFn()
	if err != nil {
		return "", err
	}

	globalFnId, err := im.getRpcFnIdentifier(r, bs, initFnVarName, rpcFnName)
	if err != nil {
		return "", fmt.Errorf("js %s function key could not be extracted: %s", rpcFnName, err.Error())
	}

	return globalFnId, nil
}

func (im *RuntimeJavascriptInitModule) getRpcFnIdentifier(r *goja.Runtime, bs *ast.BlockStatement, initFnVarName, rpcFnName string) (string, error) {
	for _, exp := range bs.List {
		if try, ok := exp.(*ast.TryStatement); ok {
			if s, err := im.getRpcFnIdentifier(r, try.Body, initFnVarName, rpcFnName); err != nil {
				continue
			} else {
				return s, nil
			}
		}
		if expStat, ok := exp.(*ast.ExpressionStatement); ok {
			if callExp, ok := expStat.Expression.(*ast.CallExpression); ok {
				if callee, ok := callExp.Callee.(*ast.DotExpression); ok {
					if callee.Left.(*ast.Identifier).Name.String() == initFnVarName && callee.Identifier.Name == "registerRpc" {
						if modNameArg, ok := callExp.ArgumentList[0].(*ast.Identifier); ok {
							id := modNameArg.Name.String()
							if r.Get(id).String() != rpcFnName {
								continue
							}
						} else if modNameArg, ok := callExp.ArgumentList[0].(*ast.StringLiteral); ok {
							if modNameArg.Value.String() != rpcFnName {
								continue
							}
						}

						if modNameArg, ok := callExp.ArgumentList[1].(*ast.Identifier); ok {
							return modNameArg.Name.String(), nil
						} else if modNameArg, ok := callExp.ArgumentList[1].(*ast.StringLiteral); ok {
							return modNameArg.Value.String(), nil
						} else {
							return "", inlinedFunctionError
						}
					}
				}
			}
		}
	}

	return "", errors.New("not found")
}

func (im *RuntimeJavascriptInitModule) registerHook(r *goja.Runtime, execMode RuntimeExecutionMode, registerFnName, fnName string) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		fn := f.Argument(0)
		_, ok := goja.AssertFunction(fn)
		if !ok {
			panic(r.NewTypeError("expects a function"))
		}

		lKey := strings.ToLower(API_PREFIX + fnName)

		fnKey, err := im.extractHookFn(registerFnName)
		if err != nil {
			panic(r.NewGoError(err))
		}
		im.registerCallbackFn(execMode, lKey, fnKey)
		im.announceCallbackFn(execMode, lKey)

		return goja.Undefined()
	}
}

func (im *RuntimeJavascriptInitModule) extractHookFn(registerFnName string) (string, error) {
	bs, initFnVarName, err := im.getInitModuleFn()
	if err != nil {
		return "", err
	}

	globalFnId, err := im.getHookFnIdentifier(bs, initFnVarName, registerFnName)
	if err != nil {
		return "", fmt.Errorf("js %s function key could not be extracted: %s", registerFnName, err.Error())
	}

	return globalFnId, nil
}

func (im *RuntimeJavascriptInitModule) getInitModuleFn() (*ast.BlockStatement, string, error) {
	var fl *ast.FunctionLiteral
	for _, dec := range im.ast.Body {
		if funDecl, ok := dec.(*ast.FunctionDeclaration); ok && funDecl.Function.Name.Name == INIT_MODULE_FN_NAME {
			fl = funDecl.Function
			break
		} else if varStat, ok := dec.(*ast.VariableStatement); ok {
			if id, ok := varStat.List[0].Target.(*ast.Identifier); ok && id.Name == INIT_MODULE_FN_NAME {
				if fnLit, ok := varStat.List[0].Initializer.(*ast.FunctionLiteral); ok {
					fl = fnLit
				}
			}
		}
	}

	if fl == nil {
		return nil, "", errors.New("failed to find InitModule function")
	}
	if len(fl.ParameterList.List) < 4 {
		return nil, "", errors.New("InitModule function is missing params")
	}

	initFnName := fl.ParameterList.List[3].Target.(*ast.Identifier).Name.String() // Initializer is the 4th argument of InitModule

	return fl.Body, initFnName, nil
}

func (im *RuntimeJavascriptInitModule) getHookFnIdentifier(bs *ast.BlockStatement, initVarName, registerFnName string) (string, error) {
	for _, exp := range bs.List {
		if try, ok := exp.(*ast.TryStatement); ok {
			if s, err := im.getHookFnIdentifier(try.Body, initVarName, registerFnName); err != nil {
				continue
			} else {
				return s, nil
			}
		}
		if expStat, ok := exp.(*ast.ExpressionStatement); ok {
			if callExp, ok := expStat.Expression.(*ast.CallExpression); ok {
				if callee, ok := callExp.Callee.(*ast.DotExpression); ok {
					if callee.Left.(*ast.Identifier).Name.String() == initVarName && callee.Identifier.Name.String() == registerFnName {
						if modNameArg, ok := callExp.ArgumentList[0].(*ast.Identifier); ok {
							return modNameArg.Name.String(), nil
						} else if modNameArg, ok := callExp.ArgumentList[0].(*ast.StringLiteral); ok {
							return modNameArg.Value.String(), nil
						} else {
							return "", errors.New("not found")
						}
					}
				}
			}
		}
	}

	return "", errors.New("not found")
}

func (im *RuntimeJavascriptInitModule) registerRtBefore(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		fName := f.Argument(0)
		if goja.IsNull(fName) || goja.IsUndefined(fName) {
			panic(r.NewTypeError("expects a non empty string"))
		}
		key, ok := fName.Export().(string)
		if !ok {
			panic(r.NewTypeError("expects a non empty string"))
		}
		if key == "" {
			panic(r.NewTypeError("expects a non empty string"))
		}

		fn := f.Argument(1)
		_, ok = goja.AssertFunction(fn)
		if !ok {
			panic(r.NewTypeError("expects a function"))
		}

		fnKey, err := im.extractRtHookFn(r, "registerRtBefore", key)
		if err != nil {
			panic(r.NewGoError(err))
		}
		lKey := strings.ToLower(RTAPI_PREFIX + key)
		im.registerCallbackFn(RuntimeExecutionModeBefore, lKey, fnKey)
		im.announceCallbackFn(RuntimeExecutionModeBefore, lKey)

		return goja.Undefined()
	}
}

func (im *RuntimeJavascriptInitModule) registerRtAfter(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		fName := f.Argument(0)
		if goja.IsNull(fName) || goja.IsUndefined(fName) {
			panic(r.NewTypeError("expects a non empty string"))
		}
		key, ok := fName.Export().(string)
		if !ok {
			panic(r.NewTypeError("expects a non empty string"))
		}
		if key == "" {
			panic(r.NewTypeError("expects a non empty string"))
		}

		fn := f.Argument(1)
		_, ok = goja.AssertFunction(fn)
		if !ok {
			panic(r.NewTypeError("expects a function"))
		}

		fnKey, err := im.extractRtHookFn(r, "registerRtAfter", key)
		if err != nil {
			panic(r.NewGoError(err))
		}
		lKey := strings.ToLower(RTAPI_PREFIX + key)
		im.registerCallbackFn(RuntimeExecutionModeAfter, lKey, fnKey)
		im.announceCallbackFn(RuntimeExecutionModeAfter, lKey)

		return goja.Undefined()
	}
}

func (im *RuntimeJavascriptInitModule) extractRtHookFn(r *goja.Runtime, registerFnName, fnName string) (string, error) {
	bs, initFnVarName, err := im.getInitModuleFn()
	if err != nil {
		return "", err
	}

	globalFnId, err := im.getRtHookFnIdentifier(r, bs, initFnVarName, registerFnName, fnName)
	if err != nil {
		return "", fmt.Errorf("js realtime %s hook function key could not be extracted: %s", registerFnName, err.Error())
	}

	return globalFnId, nil
}

func (im *RuntimeJavascriptInitModule) getRtHookFnIdentifier(r *goja.Runtime, bs *ast.BlockStatement, initVarName, registerFnName, rtFnName string) (string, error) {
	for _, exp := range bs.List {
		if try, ok := exp.(*ast.TryStatement); ok {
			if s, err := im.getRtHookFnIdentifier(r, try.Body, initVarName, registerFnName, rtFnName); err != nil {
				continue
			} else {
				return s, nil
			}
		}
		if expStat, ok := exp.(*ast.ExpressionStatement); ok {
			if callExp, ok := expStat.Expression.(*ast.CallExpression); ok {
				if callee, ok := callExp.Callee.(*ast.DotExpression); ok {
					if callee.Left.(*ast.Identifier).Name.String() == initVarName && callee.Identifier.Name.String() == registerFnName {
						if modNameArg, ok := callExp.ArgumentList[0].(*ast.Identifier); ok {
							id := modNameArg.Name.String()
							if r.Get(id).String() != rtFnName {
								continue
							}
						} else if modNameArg, ok := callExp.ArgumentList[0].(*ast.StringLiteral); ok {
							if modNameArg.Value.String() != rtFnName {
								continue
							}
						}

						if modNameArg, ok := callExp.ArgumentList[1].(*ast.Identifier); ok {
							return modNameArg.Name.String(), nil
						} else if modNameArg, ok := callExp.ArgumentList[1].(*ast.StringLiteral); ok {
							return modNameArg.Value.String(), nil
						} else {
							return "", errors.New("not found")
						}
					}
				}
			}
		}
	}

	return "", errors.New("not found")
}

func (im *RuntimeJavascriptInitModule) registerCallbackFn(mode RuntimeExecutionMode, key string, fn string) {
	switch mode {
	case RuntimeExecutionModeRPC:
		im.Callbacks.Rpc[key] = fn
	case RuntimeExecutionModeBefore:
		im.Callbacks.Before[key] = fn
	case RuntimeExecutionModeAfter:
		im.Callbacks.After[key] = fn
	}
}

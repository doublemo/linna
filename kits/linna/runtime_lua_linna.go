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
// Date: 2022-05-18 18:19:55
// LastEditors: randyma
// LastEditTime: 2022-05-18 18:20:03
// Description:

package linna

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna/cores/cronexpr"
	lua "github.com/doublemo/linna/cores/gopher-lua"
	"github.com/doublemo/linna/internal/database"
	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ctxLoggerFields struct{}

// RuntimeLuaLinnaModuleConfiguration 配置
type RuntimeLuaLinnaModuleConfiguration struct {
	Logger               *zap.Logger
	DB                   *sql.DB
	ProtojsonMarshaler   *protojson.MarshalOptions
	ProtojsonUnmarshaler *protojson.UnmarshalOptions
	Config               Configuration
	EventFn              RuntimeEventCustomFunction
	RegisterCallbackFn   func(RuntimeExecutionMode, string, *lua.LFunction)
	AnnounceCallbackFn   func(RuntimeExecutionMode, string)
	Once                 *sync.Once
	LocalCache           *RuntimeLuaLocalCache
}

type RuntimeLuaLinnaModule struct {
	logger               *zap.Logger
	db                   *sql.DB
	protojsonMarshaler   *protojson.MarshalOptions
	protojsonUnmarshaler *protojson.UnmarshalOptions
	config               Configuration
	once                 *sync.Once
	localCache           *RuntimeLuaLocalCache
	registerCallbackFn   func(RuntimeExecutionMode, string, *lua.LFunction)
	announceCallbackFn   func(RuntimeExecutionMode, string)
	client               *http.Client

	node    string
	eventFn RuntimeEventCustomFunction
}

func NewRuntimeLuaLinnaModule(c *RuntimeLuaLinnaModuleConfiguration) *RuntimeLuaLinnaModule {
	return &RuntimeLuaLinnaModule{
		logger:               c.Logger,
		db:                   c.DB,
		protojsonMarshaler:   c.ProtojsonMarshaler,
		protojsonUnmarshaler: c.ProtojsonUnmarshaler,
		once:                 c.Once,
		localCache:           c.LocalCache,
		registerCallbackFn:   c.RegisterCallbackFn,
		announceCallbackFn:   c.AnnounceCallbackFn,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		config:  c.Config,
		node:    c.Config.Endpoint.ID,
		eventFn: c.EventFn,
	}
}

func (n *RuntimeLuaLinnaModule) Loader(l *lua.LState) int {
	functions := map[string]lua.LGFunction{
		"register_rpc":         n.registerRPC,
		"register_req_before":  n.registerReqBefore,
		"register_req_after":   n.registerReqAfter,
		"register_rt_before":   n.registerRTBefore,
		"register_rt_after":    n.registerRTAfter,
		"run_once":             n.runOnce,
		"get_context":          n.getContext,
		"event":                n.event,
		"localcache_get":       n.localcacheGet,
		"localcache_put":       n.localcachePut,
		"localcache_delete":    n.localcacheDelete,
		"time":                 n.time,
		"cron_next":            n.cronNext,
		"sql_exec":             n.sqlExec,
		"sql_query":            n.sqlQuery,
		"uuid_v4":              n.uuidV4,
		"uuid_bytes_to_string": n.uuidBytesToString,
		"uuid_string_to_bytes": n.uuidStringToBytes,
		"http_request":         n.httpRequest,
		"jwt_generate":         n.jwtGenerate,
		"json_encode":          n.jsonEncode,
		"json_decode":          n.jsonDecode,
		"base64_encode":        n.base64Encode,
		"base64_decode":        n.base64Decode,
		"base64url_encode":     n.base64URLEncode,
		"base64url_decode":     n.base64URLDecode,
		"base16_encode":        n.base16Encode,
		"base16_decode":        n.base16Decode,
		"aes128_encrypt":       n.aes128Encrypt,
		"aes128_decrypt":       n.aes128Decrypt,
		"aes256_encrypt":       n.aes256Encrypt,
		"aes256_decrypt":       n.aes256Decrypt,
		"md5_hash":             n.md5Hash,
		"sha256_hash":          n.sha256Hash,
		"hmac_sha256_hash":     n.hmacSHA256Hash,
		"rsa_sha256_hash":      n.rsaSHA256Hash,
		"bcrypt_hash":          n.bcryptHash,
		"bcrypt_compare":       n.bcryptCompare,
		"logger_debug":         n.loggerDebug,
		"logger_info":          n.loggerInfo,
		"logger_warn":          n.loggerWarn,
		"logger_error":         n.loggerError,
	}

	mod := l.SetFuncs(l.CreateTable(0, len(functions)), functions)

	l.Push(mod)
	return 1
}

// @group hooks
// @summary Registers a function for use with client RPC to the server.
// @param fn(type=function) A function reference which will be executed on each RPC message.
// @param id(type=string) The unique identifier used to register the function for RPC.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) registerRPC(l *lua.LState) int {
	fn := l.CheckFunction(1)
	id := l.CheckString(2)

	if id == "" {
		l.ArgError(2, "expects rpc id")
		return 0
	}

	id = strings.ToLower(id)

	if n.registerCallbackFn != nil {
		n.registerCallbackFn(RuntimeExecutionModeRPC, id, fn)
	}
	if n.announceCallbackFn != nil {
		n.announceCallbackFn(RuntimeExecutionModeRPC, id)
	}
	return 0
}

// @group hooks
// @summary Register a function with the server which will be executed before any non-realtime message with the specified message name.
// @param fn(type=function) A function reference which will be executed on each message.
// @param id(type=string) The specific message name to execute the function after.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) registerReqBefore(l *lua.LState) int {
	fn := l.CheckFunction(1)
	id := l.CheckString(2)

	if id == "" {
		l.ArgError(2, "expects method name")
		return 0
	}

	id = strings.ToLower(API_PREFIX + id)

	if n.registerCallbackFn != nil {
		n.registerCallbackFn(RuntimeExecutionModeBefore, id, fn)
	}
	if n.announceCallbackFn != nil {
		n.announceCallbackFn(RuntimeExecutionModeBefore, id)
	}
	return 0
}

// @group hooks
// @summary Register a function with the server which will be executed after every non-realtime message as specified while registering the function.
// @param fn(type=function) A function reference which will be executed on each message.
// @param id(type=string) The specific message name to execute the function after.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) registerReqAfter(l *lua.LState) int {
	fn := l.CheckFunction(1)
	id := l.CheckString(2)

	if id == "" {
		l.ArgError(2, "expects method name")
		return 0
	}

	id = strings.ToLower(API_PREFIX + id)

	if n.registerCallbackFn != nil {
		n.registerCallbackFn(RuntimeExecutionModeAfter, id, fn)
	}
	if n.announceCallbackFn != nil {
		n.announceCallbackFn(RuntimeExecutionModeAfter, id)
	}
	return 0
}

// @group hooks
// @summary Register a function with the server which will be executed before any realtime message with the specified message name.
// @param fn(type=function) A function reference which will be executed on each msgname message. The function should pass the payload input back as a return argument so the pipeline can continue to execute the standard logic.
// @param id(type=string) The specific message name to execute the function after.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) registerRTBefore(l *lua.LState) int {
	fn := l.CheckFunction(1)
	id := l.CheckString(2)

	if id == "" {
		l.ArgError(2, "expects message name")
		return 0
	}

	id = strings.ToLower(RTAPI_PREFIX + id)

	if n.registerCallbackFn != nil {
		n.registerCallbackFn(RuntimeExecutionModeBefore, id, fn)
	}
	if n.announceCallbackFn != nil {
		n.announceCallbackFn(RuntimeExecutionModeBefore, id)
	}
	return 0
}

// @group hooks
// @summary Register a function with the server which will be executed after every realtime message with the specified message name.
// @param fn(type=function) A function reference which will be executed on each msgname message.
// @param id(type=string) The specific message name to execute the function after.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) registerRTAfter(l *lua.LState) int {
	fn := l.CheckFunction(1)
	id := l.CheckString(2)

	if id == "" {
		l.ArgError(2, "expects message name")
		return 0
	}

	id = strings.ToLower(RTAPI_PREFIX + id)

	if n.registerCallbackFn != nil {
		n.registerCallbackFn(RuntimeExecutionModeAfter, id, fn)
	}
	if n.announceCallbackFn != nil {
		n.announceCallbackFn(RuntimeExecutionModeAfter, id)
	}
	return 0
}

// @group hooks
// @summary Registers a function to be run only once.
// @param fn(type=function) A function reference which will be executed only once.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) runOnce(l *lua.LState) int {
	n.once.Do(func() {
		fn := l.CheckFunction(1)
		if fn == nil {
			l.ArgError(1, "expects a function")
			return
		}

		ctx := NewRuntimeLuaContext(l, RuntimeExecutionModeRunOnce, &RuntimeContextConfiguration{
			Node: n.config.Endpoint.ID,
			Env:  n.config.Runtime.Environment,
		})

		l.Push(LSentinel)
		l.Push(fn)
		l.Push(ctx)
		if err := l.PCall(1, lua.MultRet, nil); err != nil {
			l.RaiseError("error in run_once function: %v", err.Error())
			return
		}

		// Unwind the stack up to and including our sentinel value, effectively discarding any returned parameters.
		for {
			v := l.Get(-1)
			l.Pop(1)
			if v.Type() == LTSentinel {
				break
			}
		}
	})

	return 0
}

func (n *RuntimeLuaLinnaModule) getContext(l *lua.LState) int {
	ctx := NewRuntimeLuaContext(l, RuntimeExecutionModeRunOnce, &RuntimeContextConfiguration{
		Node: n.config.Endpoint.ID,
		Env:  n.config.Runtime.Environment,
	})
	l.Push(ctx)
	return 1
}

// @group events
// @summary Generate an event.
// @param name(type=string) The name of the event to be created.
// @param properties(type=OptTable) A table of event properties.
// @param timestamp(type=int64) Numeric UTC value of when event is created.
// @param external(type=bool, optional=true, default=false) Whether the event is external.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) event(l *lua.LState) int {
	name := l.CheckString(1)
	if name == "" {
		l.ArgError(1, "expects name string")
		return 0
	}

	propertiesTable := l.OptTable(2, nil)
	var properties map[string]string
	if propertiesTable != nil {
		var conversionError bool
		properties = make(map[string]string, propertiesTable.Len())
		propertiesTable.ForEach(func(k lua.LValue, v lua.LValue) {
			if conversionError {
				return
			}

			if k.Type() != lua.LTString {
				l.ArgError(2, "properties keys must be strings")
				conversionError = true
				return
			}
			if v.Type() != lua.LTString {
				l.ArgError(2, "properties values must be strings")
				conversionError = true
				return
			}

			properties[k.String()] = v.String()
		})

		if conversionError {
			return 0
		}
	}

	var ts *timestamppb.Timestamp
	t := l.Get(3)
	if t != lua.LNil {
		if t.Type() != lua.LTNumber {
			l.ArgError(3, "timestamp must be numeric UTC seconds when provided")
			return 0
		}
		ts = &timestamppb.Timestamp{Seconds: int64(t.(lua.LNumber))}
	}

	external := l.OptBool(4, false)

	if n.eventFn != nil {
		n.eventFn(l.Context(), &api.Event{
			Name:       name,
			Properties: properties,
			Timestamp:  ts,
			External:   external,
		})
	}
	return 0
}

func (n *RuntimeLuaLinnaModule) localcacheGet(l *lua.LState) int {
	key := l.CheckString(1)
	if key == "" {
		l.ArgError(1, "expects key string")
		return 0
	}

	defaultValue := l.Get(2)

	value, found := n.localCache.Get(key)

	if found {
		l.Push(value)
	} else {
		l.Push(defaultValue)
	}
	return 1
}

func (n *RuntimeLuaLinnaModule) localcachePut(l *lua.LState) int {
	key := l.CheckString(1)
	if key == "" {
		l.ArgError(1, "expects key string")
		return 0
	}

	value := l.Get(2)
	if valueTable, ok := value.(*lua.LTable); ok {
		valueTable.SetReadOnlyRecursive()
	}

	n.localCache.Put(key, value)

	return 0
}

func (n *RuntimeLuaLinnaModule) localcacheDelete(l *lua.LState) int {
	key := l.CheckString(1)
	if key == "" {
		l.ArgError(1, "expects key string")
		return 0
	}

	n.localCache.Delete(key)

	return 0
}

// @group utils
// @summary Get the current UTC time in milliseconds using the system wall clock.
// @return t(int) A number representing the current UTC time in milliseconds.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) time(l *lua.LState) int {
	if l.GetTop() == 0 {
		l.Push(lua.LNumber(time.Now().UTC().UnixNano() / int64(time.Millisecond)))
	} else {
		tbl := l.CheckTable(1)
		msec := getIntField(l, tbl, "msec", 0)
		sec := getIntField(l, tbl, "sec", 0)
		min := getIntField(l, tbl, "min", 0)
		hour := getIntField(l, tbl, "hour", 12)
		day := getIntField(l, tbl, "day", -1)
		month := getIntField(l, tbl, "month", -1)
		year := getIntField(l, tbl, "year", -1)
		isdst := getBoolField(l, tbl, "isdst", false)
		t := time.Date(year, time.Month(month), day, hour, min, sec, msec*int(time.Millisecond), time.UTC)
		// TODO dst
		if false {
			print(isdst)
		}
		l.Push(lua.LNumber(t.UTC().UnixNano() / int64(time.Millisecond)))
	}
	return 1
}

// @group utils
// @summary Parses a CRON expression and a timestamp in UTC seconds, and returns the next matching timestamp in UTC seconds.
// @param expression(type=string) A valid CRON expression in standard format, for example "0 0 * * *" (meaning at midnight).
// @param timestamp(type=number) A time value expressed as UTC seconds.
// @return next_ts(number) The next UTC seconds timestamp (number) that matches the given CRON expression, and is immediately after the given timestamp.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) cronNext(l *lua.LState) int {
	cron := l.CheckString(1)
	if cron == "" {
		l.ArgError(1, "expects cron string")
		return 0
	}
	ts := l.CheckInt64(2)
	if ts == 0 {
		l.ArgError(1, "expects timestamp in seconds")
		return 0
	}

	expr, err := cronexpr.Parse(cron)
	if err != nil {
		l.ArgError(1, "expects a valid cron string")
		return 0
	}
	t := time.Unix(ts, 0).UTC()
	next := expr.Next(t)
	nextTs := next.UTC().Unix()
	l.Push(lua.LNumber(nextTs))
	return 1
}

// @group utils
// @summary Execute an arbitrary SQL query and return the number of rows affected. Typically an "INSERT", "DELETE", or "UPDATE" statement with no return columns.
// @param query(type=string) A SQL query to execute.
// @param parameters(type=table) Arbitrary parameters to pass to placeholders in the query.
// @return count(number) A list of matches matching the parameters criteria.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) sqlExec(l *lua.LState) int {
	query := l.CheckString(1)
	if query == "" {
		l.ArgError(1, "expects query string")
		return 0
	}
	paramsTable := l.OptTable(2, nil)
	var params []interface{}
	if paramsTable != nil && paramsTable.Len() != 0 {
		var ok bool
		params, ok = RuntimeLuaConvertLuaValue(paramsTable).([]interface{})
		if !ok {
			l.ArgError(2, "expects a list of params as a table")
			return 0
		}
	}

	var result sql.Result
	var err error
	err = database.ExecuteRetryable(func() error {
		result, err = n.db.ExecContext(l.Context(), query, params...)
		return err
	})
	if err != nil {
		l.RaiseError("sql exec error: %v", err.Error())
		return 0
	}
	count, err := result.RowsAffected()
	if err != nil {
		l.RaiseError("sql exec rows affected error: %v", err.Error())
		return 0
	}

	l.Push(lua.LNumber(count))
	return 1
}

// @group utils
// @summary Execute an arbitrary SQL query that is expected to return row data. Typically a "SELECT" statement.
// @param query(type=string) A SQL query to execute.
// @param parameters(type=table) Arbitrary parameters to pass to placeholders in the query.
// @return result(table) A table of rows and the respective columns and values.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) sqlQuery(l *lua.LState) int {
	query := l.CheckString(1)
	if query == "" {
		l.ArgError(1, "expects query string")
		return 0
	}
	paramsTable := l.OptTable(2, nil)
	var params []interface{}
	if paramsTable != nil && paramsTable.Len() != 0 {
		var ok bool
		params, ok = RuntimeLuaConvertLuaValue(paramsTable).([]interface{})
		if !ok {
			l.ArgError(2, "expects a list of params as a table")
			return 0
		}
	}

	var rows *sql.Rows
	var err error
	err = database.ExecuteRetryable(func() error {
		rows, err = n.db.QueryContext(l.Context(), query, params...)
		return err
	})
	if err != nil {
		l.RaiseError("sql query error: %v", err.Error())
		return 0
	}
	defer rows.Close()

	resultColumns, err := rows.Columns()
	if err != nil {
		l.RaiseError("sql query column lookup error: %v", err.Error())
		return 0
	}
	resultColumnCount := len(resultColumns)
	resultRows := make([][]interface{}, 0)
	for rows.Next() {
		resultRowValues := make([]interface{}, resultColumnCount)
		resultRowPointers := make([]interface{}, resultColumnCount)
		for i := range resultRowValues {
			resultRowPointers[i] = &resultRowValues[i]
		}
		if err = rows.Scan(resultRowPointers...); err != nil {
			l.RaiseError("sql query scan error: %v", err.Error())
			return 0
		}
		resultRows = append(resultRows, resultRowValues)
	}
	if err = rows.Err(); err != nil {
		l.RaiseError("sql query row scan error: %v", err.Error())
		return 0
	}

	rt := l.CreateTable(len(resultRows), 0)
	for i, r := range resultRows {
		rowTable := l.CreateTable(0, resultColumnCount)
		for j, col := range resultColumns {
			rowTable.RawSetString(col, RuntimeLuaConvertValue(l, r[j]))
		}
		rt.RawSetInt(i+1, rowTable)
	}
	l.Push(rt)
	return 1
}

// @group utils
// @summary Generate a version 4 UUID in the standard 36-character string representation.
// @return u(string) The newly generated version 4 UUID identifier string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) uuidV4(l *lua.LState) int {
	l.Push(lua.LString(uuid.Must(uuid.NewV4()).String()))
	return 1
}

// @group utils
// @summary Convert the 16-byte raw representation of a UUID into the equivalent 36-character standard UUID string representation. Will raise an error if the input is not valid and cannot be converted.
// @param uuid_bytes(type=string) The UUID bytes to convert.
// @return u(string) A string containing the equivalent 36-character standard representation of the UUID.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) uuidBytesToString(l *lua.LState) int {
	uuidBytes := l.CheckString(1)
	if uuidBytes == "" {
		l.ArgError(1, "expects a UUID byte string")
		return 0
	}
	u, err := uuid.FromBytes([]byte(uuidBytes))
	if err != nil {
		l.ArgError(1, "not a valid UUID byte string")
		return 0
	}
	l.Push(lua.LString(u.String()))
	return 1
}

// @group utils
// @summary Convert the 36-character string representation of a UUID into the equivalent 16-byte raw UUID representation. Will raise an error if the input is not valid and cannot be converted.
// @param uuid_string(type=string) The UUID string to convert.
// @return u(string) A string containing the equivalent 16-byte representation of the UUID.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) uuidStringToBytes(l *lua.LState) int {
	uuidString := l.CheckString(1)
	if uuidString == "" {
		l.ArgError(1, "expects a UUID string")
		return 0
	}
	u, err := uuid.FromString(uuidString)
	if err != nil {
		l.ArgError(1, "not a valid UUID string")
		return 0
	}
	l.Push(lua.LString(u.Bytes()))
	return 1
}

// @group utils
// @summary Send a HTTP request that returns a data type containing the result of the HTTP response.
// @param url(type=string) The URL of the web resource to request.
// @param method(type=string) The HTTP method verb used with the request.
// @param headers(type=OptTable, optional=true) A table of headers used with the request.
// @param content(type=OptString, optional=true) The bytes to send with the request.
// @param timeout(type=OptNumber, optional=true, default=5000) Timeout of the request in milliseconds.
// @return returnVal(table) Code, Headers, and Body response values for the HTTP response.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) httpRequest(l *lua.LState) int {
	url := l.CheckString(1)
	method := l.CheckString(2)
	headers := l.CheckTable(3)
	body := l.OptString(4, "")
	if url == "" {
		l.ArgError(1, "expects URL string")
		return 0
	}
	if method == "" {
		l.ArgError(2, "expects method string")
		return 0
	}

	// Set a custom timeout if one is provided, or use the default.
	timeoutMs := l.OptInt64(5, 5000)
	n.client.Timeout = time.Duration(timeoutMs) * time.Millisecond

	// Prepare request body, if any.
	var requestBody io.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	// Prepare the request.
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		l.RaiseError("HTTP request error: %v", err.Error())
		return 0
	}
	// Apply any request headers.
	httpHeaders := RuntimeLuaConvertLuaTable(headers)
	for k, v := range httpHeaders {
		vs, ok := v.(string)
		if !ok {
			l.RaiseError("HTTP header values must be strings")
			return 0
		}
		req.Header.Add(k, vs)
	}
	// Execute the request.
	resp, err := n.client.Do(req)
	if err != nil {
		l.RaiseError("HTTP request error: %v", err.Error())
		return 0
	}
	// Read the response body.
	responseBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		l.RaiseError("HTTP response body error: %v", err.Error())
		return 0
	}
	// Read the response headers.
	responseHeaders := make(map[string]interface{}, len(resp.Header))
	for k, vs := range resp.Header {
		// TODO accept multiple values per header
		for _, v := range vs {
			responseHeaders[k] = v
			break
		}
	}

	l.Push(lua.LNumber(resp.StatusCode))
	l.Push(RuntimeLuaConvertMap(l, responseHeaders))
	l.Push(lua.LString(string(responseBody)))
	return 3
}

// @group utils
// @summary Generate a JSON Web Token.
// @param signingMethod(type=string) The signing method to be used, either HS256 or RS256.
// @param signingKey(type=string) The signing key to be used.
// @param claims(type=table) The JWT payload.
// @return token(string) The newly generated JWT.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) jwtGenerate(l *lua.LState) int {
	algoType := l.CheckString(1)
	if algoType == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	var signingMethod jwt.SigningMethod
	switch algoType {
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	default:
		l.ArgError(1, "unsupported algo type - only allowed 'HS256', 'RS256'.")
		return 0
	}

	signingKey := l.CheckString(2)
	if signingKey == "" {
		l.ArgError(2, "expects string")
		return 0
	}

	claimsetTable := l.CheckTable(3)
	if claimsetTable == nil {
		l.ArgError(3, "expects nil")
		return 0
	}

	claimset := RuntimeLuaConvertLuaValue(claimsetTable).(map[string]interface{})
	jwtClaims := jwt.MapClaims{}
	for k, v := range claimset {
		jwtClaims[k] = v
	}

	var pk interface{}
	switch signingMethod {
	case jwt.SigningMethodRS256:
		block, _ := pem.Decode([]byte(signingKey))
		if block == nil {
			l.RaiseError("could not parse private key: no valid blocks found")
			return 0
		}

		var err error
		pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			l.RaiseError("could not parse private key: %v", err.Error())
			return 0
		}
	case jwt.SigningMethodHS256:
		pk = []byte(signingKey)
	}

	token := jwt.NewWithClaims(signingMethod, jwtClaims)
	signedToken, err := token.SignedString(pk)
	if err != nil {
		l.RaiseError("failed to sign token: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(signedToken))
	return 1
}

// @group utils
// @summary Encode the input as JSON.
// @param value(type=string) The input to encode as JSON .
// @return jsonBytes(string) The encoded JSON string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) jsonEncode(l *lua.LState) int {
	value := l.Get(1)
	if value == nil {
		l.ArgError(1, "expects a non-nil value to encode")
		return 0
	}

	jsonData := RuntimeLuaConvertLuaValue(value)
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		l.RaiseError("error encoding to JSON: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(string(jsonBytes)))
	return 1
}

// @group utils
// @summary Decode the JSON input as a Lua table.
// @param jsonString(type=string) The JSON encoded input.
// @return jsonData(table) Decoded JSON input as a Lua table.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) jsonDecode(l *lua.LState) int {
	jsonString := l.CheckString(1)
	if jsonString == "" {
		l.ArgError(1, "expects JSON string")
		return 0
	}

	var jsonData interface{}
	if err := json.Unmarshal([]byte(jsonString), &jsonData); err != nil {
		l.RaiseError("not a valid JSON string: %v", err.Error())
		return 0
	}

	l.Push(RuntimeLuaConvertValue(l, jsonData))
	return 1
}

// @group utils
// @summary Base64 encode a string input.
// @param input(type=string) The string which will be base64 encoded.
// @return output(string) Encoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) base64Encode(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	padding := l.OptBool(2, true)

	e := base64.StdEncoding
	if !padding {
		e = base64.RawStdEncoding
	}
	output := e.EncodeToString([]byte(input))
	l.Push(lua.LString(output))
	return 1
}

// @group utils
// @summary Decode a base64 encoded string.
// @param input(type=string) The string which will be base64 decoded.
// @return output(string) Decoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) base64Decode(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	padding := l.OptBool(2, false)

	if !padding {
		// Pad string up to length multiple of 4 if needed to effectively make padding optional.
		if maybePad := len(input) % 4; maybePad != 0 {
			input += strings.Repeat("=", 4-maybePad)
		}
	}

	output, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		l.RaiseError("not a valid base64 string: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(output))
	return 1
}

// @group utils
// @summary Base64 URL encode a string input.
// @param input(type=string) The string which will be base64 URL encoded.
// @return output(string) Encoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) base64URLEncode(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	padding := l.OptBool(2, true)

	e := base64.URLEncoding
	if !padding {
		e = base64.RawURLEncoding
	}
	output := e.EncodeToString([]byte(input))
	l.Push(lua.LString(output))
	return 1
}

// @group utils
// @summary Decode a base64 URL encoded string.
// @param input(type=string) The string to be decoded.
// @return output(string) Decoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) base64URLDecode(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	padding := l.OptBool(2, false)

	if !padding {
		// Pad string up to length multiple of 4 if needed to effectively make padding optional.
		if maybePad := len(input) % 4; maybePad != 0 {
			input += strings.Repeat("=", 4-maybePad)
		}
	}

	output, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		l.RaiseError("not a valid base64 url string: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(output))
	return 1
}

// @group utils
// @summary base16 encode a string input.
// @param input(type=string) The string to be encoded.
// @return output(string) Encoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) base16Encode(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	output := hex.EncodeToString([]byte(input))
	l.Push(lua.LString(output))
	return 1
}

// @group utils
// @summary Decode a base16 encoded string.
// @param input(type=string) The string to be decoded.
// @return output(string) Decoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) base16Decode(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	output, err := hex.DecodeString(input)
	if err != nil {
		l.RaiseError("not a valid base16 string: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(output))
	return 1
}

// Not annotated as not exported and available in the Lua runtime
func aesEncrypt(l *lua.LState, keySize int) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}
	key := l.CheckString(2)
	if len(key) != keySize {
		l.ArgError(2, fmt.Sprintf("expects key %v bytes long", keySize))
		return 0
	}

	// Pad string up to length multiple of 4 if needed.
	if maybePad := len(input) % 4; maybePad != 0 {
		input += strings.Repeat(" ", 4-maybePad)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		l.RaiseError("error creating cipher block: %v", err.Error())
		return 0
	}

	cipherText := make([]byte, aes.BlockSize+len(input))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		l.RaiseError("error getting iv: %v", err.Error())
		return 0
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(input))

	l.Push(lua.LString(cipherText))
	return 1
}

// Not annotated as not exported and available in the Lua runtime
func aesDecrypt(l *lua.LState, keySize int) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}
	key := l.CheckString(2)
	if len(key) != keySize {
		l.ArgError(2, fmt.Sprintf("expects key %v bytes long", keySize))
		return 0
	}

	if len(input) < aes.BlockSize {
		l.RaiseError("input too short")
		return 0
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		l.RaiseError("error creating cipher block: %v", err.Error())
		return 0
	}

	cipherText := []byte(input)
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	l.Push(lua.LString(cipherText))
	return 1
}

// @group utils
// @summary aes128 encrypt a string input.
// @param input(type=string) The string which will be aes128 encrypted.
// @param key(type=string) The 16 Byte encryption key.
// @return cipherText(string) The ciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) aes128Encrypt(l *lua.LState) int {
	return aesEncrypt(l, 16)
}

// @group utils
// @summary Decrypt an aes128 encrypted string.
// @param input(type=string) The string to be decrypted.
// @param key(type=string) The 16 Byte decryption key.
// @return clearText(string) The deciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) aes128Decrypt(l *lua.LState) int {
	return aesDecrypt(l, 16)
}

// @group utils
// @summary aes256 encrypt a string input.
// @param input(type=string) The string which will be aes256 encrypted.
// @param key(type=string) The 32 Byte encryption key.
// @return cipherText(string) The ciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) aes256Encrypt(l *lua.LState) int {
	return aesEncrypt(l, 32)
}

// @group utils
// @summary Decrypt an aes256 encrypted string.
// @param input(type=string) The string to be decrypted.
// @param key(type=string) The 32 Byte decryption key.
// @return clearText(string) The deciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) aes256Decrypt(l *lua.LState) int {
	return aesDecrypt(l, 32)
}

// @group utils
// @summary Create an md5 hash from the input.
// @param input(type=string) The input string to hash.
// @return hash(string) A string with the md5 hash of the input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) md5Hash(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects input string")
		return 0
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(input)))

	l.Push(lua.LString(hash))
	return 1
}

// @group utils
// @summary Create an SHA256 hash from the input.
// @param input(type=string) The input string to hash.
// @return hash(string) A string with the SHA256 hash of the input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) sha256Hash(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects input string")
		return 0
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(input)))

	l.Push(lua.LString(hash))
	return 1
}

// @group utils
// @summary Create a RSA encrypted SHA256 hash from the input.
// @param input(type=string) The input string to hash.
// @param key(type=string) The RSA private key.
// @return signature(string) A string with the RSA encrypted SHA256 hash of the input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) rsaSHA256Hash(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects input string")
		return 0
	}
	key := l.CheckString(2)
	if key == "" {
		l.ArgError(2, "expects key string")
		return 0
	}

	block, _ := pem.Decode([]byte(key))
	if block == nil {
		l.RaiseError("could not parse private key: no valid blocks found")
		return 0
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		l.RaiseError("error parsing key: %v", err.Error())
		return 0
	}

	hashed := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		l.RaiseError("error signing input: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(signature))
	return 1
}

// @group utils
// @summary Create a HMAC-SHA256 hash from input and key.
// @param input(type=string) The input string to hash.
// @param key(type=string) The hashing key.
// @return mac(string) Hashed input as a string using the key.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) hmacSHA256Hash(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects input string")
		return 0
	}
	key := l.CheckString(2)
	if key == "" {
		l.ArgError(2, "expects key string")
		return 0
	}

	mac := hmac.New(sha256.New, []byte(key))
	_, err := mac.Write([]byte(input))
	if err != nil {
		l.RaiseError("error creating hash: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(mac.Sum(nil)))
	return 1
}

// @group utils
// @summary Generate one-way hashed string using bcrypt.
// @param input(type=string) The input string to bcrypt.
// @return hash(string) Hashed string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) bcryptHash(l *lua.LState) int {
	input := l.CheckString(1)
	if input == "" {
		l.ArgError(1, "expects string")
		return 0
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	if err != nil {
		l.RaiseError("error hashing input: %v", err.Error())
		return 0
	}

	l.Push(lua.LString(hash))
	return 1
}

// @group utils
// @summary Compare hashed input against a plaintext input.
// @param hash(type=string) The bcrypted input string.
// @param plaintext(type=string) Plaintext input to compare against.
// @return result(bool) True if they are the same, false otherwise.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) bcryptCompare(l *lua.LState) int {
	hash := l.CheckString(1)
	if hash == "" {
		l.ArgError(1, "expects string")
		return 0
	}
	plaintext := l.CheckString(2)
	if plaintext == "" {
		l.ArgError(2, "expects string")
		return 0
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	if err == nil {
		l.Push(lua.LBool(true))
		return 1
	} else if err == bcrypt.ErrHashTooShort || err == bcrypt.ErrMismatchedHashAndPassword {
		l.Push(lua.LBool(false))
		return 1
	}

	l.RaiseError("error comparing hash and plaintext: %v", err.Error())
	return 0
}

func (n *RuntimeLuaLinnaModule) getLuaModule(l *lua.LState) string {
	// "path/to/module.lua:123:"
	src := l.Where(-1)
	// "path/to/module.lua:123"
	return strings.TrimPrefix(src[:len(src)-1], n.config.Runtime.Path)
}

// @group logger
// @summary Write a DEBUG level message to the server logs.
// @param message(type=string) The message to write to server logs with DEBUG level severity.
// @param vars(type=vars) Variables to replace placeholders in message.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) loggerDebug(l *lua.LState) int {
	message := l.CheckString(1)
	if message == "" {
		l.ArgError(1, "expects message string")
		return 0
	}

	ctxLogFields := l.Context().Value(ctxLoggerFields{})
	if ctxLogFields != nil {
		logFields, ok := ctxLogFields.(map[string]string)
		if ok {
			fields := make([]zap.Field, 0, len(logFields)+1)
			fields = append(fields, zap.String("runtime", "lua"))
			for key, val := range logFields {
				fields = append(fields, zap.String(key, val))
			}
			n.logger.Debug(message, fields...)
		}
	} else {
		n.logger.Debug(message, zap.String("runtime", "lua"))
	}

	l.Push(lua.LString(message))
	return 1
}

// @group logger
// @summary Write an INFO level message to the server logs.
// @param message(type=string) The message to write to server logs with INFO level severity.
// @param vars(type=vars) Variables to replace placeholders in message.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) loggerInfo(l *lua.LState) int {
	message := l.CheckString(1)
	if message == "" {
		l.ArgError(1, "expects message string")
		return 0
	}

	ctxLogFields := l.Context().Value(ctxLoggerFields{})
	if ctxLogFields != nil {
		logFields, ok := ctxLogFields.(map[string]string)
		if ok {
			fields := make([]zap.Field, 0, len(logFields)+1)
			fields = append(fields, zap.String("runtime", "lua"))
			for key, val := range logFields {
				fields = append(fields, zap.String(key, val))
			}
			n.logger.Info(message, fields...)
		}
	} else {
		n.logger.Info(message, zap.String("runtime", "lua"))
	}

	l.Push(lua.LString(message))
	return 1
}

// @group logger
// @summary Write a WARN level message to the server logs.
// @param message(type=string) The message to write to server logs with WARN level severity.
// @param vars(type=vars) Variables to replace placeholders in message.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) loggerWarn(l *lua.LState) int {
	message := l.CheckString(1)
	if message == "" {
		l.ArgError(1, "expects message string")
		return 0
	}

	ctxLogFields := l.Context().Value(ctxLoggerFields{})
	if ctxLogFields != nil {
		logFields, ok := ctxLogFields.(map[string]string)
		if ok {
			fields := make([]zap.Field, 0, len(logFields)+1)
			fields = append(fields, zap.String("runtime", "lua"))
			for key, val := range logFields {
				fields = append(fields, zap.String(key, val))
			}
			n.logger.Warn(message, fields...)
		}
	} else {
		n.logger.Warn(message, zap.String("runtime", "lua"))
	}

	l.Push(lua.LString(message))
	return 1
}

// @group logger
// @summary Write an ERROR level message to the server logs.
// @param message(type=string) The message to write to server logs with ERROR level severity.
// @param vars(type=vars) Variables to replace placeholders in message.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeLuaLinnaModule) loggerError(l *lua.LState) int {
	message := l.CheckString(1)
	if message == "" {
		l.ArgError(1, "expects message string")
		return 0
	}

	ctxLogFields := l.Context().Value(ctxLoggerFields{})
	if ctxLogFields != nil {
		logFields, ok := ctxLogFields.(map[string]string)
		if ok {
			fields := make([]zap.Field, 0, len(logFields)+1)
			fields = append(fields, zap.String("runtime", "lua"))
			for key, val := range logFields {
				fields = append(fields, zap.String(key, val))
			}
			n.logger.Error(message, fields...)
		}
	} else {
		n.logger.Error(message, zap.String("runtime", "lua"), zap.String("source", n.getLuaModule(l)))
	}

	l.Push(lua.LString(message))
	return 1
}

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
// Date: 2022-05-17 09:52:23
// LastEditors: randyma
// LastEditTime: 2022-05-17 09:52:32
// Description:

package linna

import (
	"context"
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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
	"github.com/doublemo/linna-common/api"
	"github.com/doublemo/linna/cores/cronexpr"
	"github.com/doublemo/linna/internal/database"
	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RuntimeJavascriptLinnaModuleConfiguration 运行时间创建module参数
type RuntimeJavascriptLinnaModuleConfiguration struct {
	Logger               *zap.Logger
	DB                   *sql.DB
	ProtojsonMarshaler   *protojson.MarshalOptions
	ProtojsonUnmarshaler *protojson.UnmarshalOptions
	Config               Configuration
	Node                 string
	eventFn              RuntimeEventCustomFunction
}

// RuntimeJavascriptLinnaModule 运行Linna模块
type RuntimeJavascriptLinnaModule struct {
	logger               *zap.Logger
	db                   *sql.DB
	protojsonMarshaler   *protojson.MarshalOptions
	protojsonUnmarshaler *protojson.UnmarshalOptions
	config               Configuration
	localCache           *RuntimeJavascriptLocalCache
	httpClient           *http.Client

	eventFn RuntimeEventCustomFunction
	node    string
}

func (n *RuntimeJavascriptLinnaModule) Constructor(r *goja.Runtime) func(goja.ConstructorCall) *goja.Object {
	return func(call goja.ConstructorCall) *goja.Object {
		for fnName, fn := range n.mappings(r) {
			call.This.Set(fnName, fn)
		}
		freeze(call.This)
		return nil
	}
}

func (n *RuntimeJavascriptLinnaModule) mappings(r *goja.Runtime) map[string]func(goja.FunctionCall) goja.Value {
	return map[string]func(goja.FunctionCall) goja.Value{
		"event":           n.event(r),
		"uuidv4":          n.uuidV4(r),
		"cronNext":        n.cronNext(r),
		"sqlExec":         n.sqlExec(r),
		"sqlQuery":        n.sqlQuery(r),
		"httpRequest":     n.httpRequest(r),
		"base64Encode":    n.base64Encode(r),
		"base64Decode":    n.base64Decode(r),
		"base64UrlEncode": n.base64UrlEncode(r),
		"base64UrlDecode": n.base64UrlDecode(r),
		"base16Encode":    n.base16Encode(r),
		"base16Decode":    n.base16Decode(r),
		"jwtGenerate":     n.jwtGenerate(r),
		"aes128Encrypt":   n.aes128Encrypt(r),
		"aes128Decrypt":   n.aes128Decrypt(r),
		"aes256Encrypt":   n.aes256Encrypt(r),
		"aes256Decrypt":   n.aes256Decrypt(r),
		"md5Hash":         n.md5Hash(r),
		"sha256Hash":      n.sha256Hash(r),
		"hmacSha256Hash":  n.hmacSHA256Hash(r),
		"rsaSha256Hash":   n.rsaSHA256Hash(r),
		"bcryptHash":      n.bcryptHash(r),
		"bcryptCompare":   n.bcryptCompare(r),
		"binaryToString":  n.binaryToString(r),
		"stringToBinary":  n.stringToBinary(r),
	}
}

// @group utils
// @summary Convert binary data to string.
// @param data(type=Uint8Array) The binary data to be converted.
// @return result(type=string) The resulting string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) binaryToString(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		if goja.IsUndefined(f.Argument(0)) || goja.IsNull(f.Argument(0)) {
			panic(r.NewTypeError("expects a Uint8Array object"))
		}

		data, ok := f.Argument(0).Export().(goja.ArrayBuffer)
		if !ok {
			panic(r.NewTypeError("expects a Uint8Array object"))
		}

		if !utf8.Valid(data.Bytes()) {
			panic(r.NewTypeError("expects data to be UTF-8 encoded"))
		}

		return r.ToValue(string(data.Bytes()))
	}
}

// @group utils
// @summary Convert string data to binary.
// @param str(type=string) The string to be converted.
// @return result(type=Uint8Array) The resulting binary data.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) stringToBinary(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		if goja.IsUndefined(f.Argument(0)) || goja.IsNull(f.Argument(0)) {
			panic(r.NewTypeError("expects a string"))
		}

		str, ok := f.Argument(0).Export().(string)
		if !ok {
			panic(r.NewTypeError("expects a string"))
		}

		return r.ToValue([]byte(str))
	}
}

// @group utils
// @summary Generate a version 4 UUID in the standard 36-character string representation.
// @return uuid(string) The newly generated version 4 UUID identifier string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) uuidV4(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		return r.ToValue(uuid.Must(uuid.NewV4()).String())
	}
}

// @group events
// @summary Generate an event.
// @param event_name(type=string) The name of the event to be created.
// @param properties(type=[]string) An array of event properties.
// @param ts(type=int, optional=true) Timestamp for when event is created.
// @param external(type=bool, optional=true, default=false) Whether the event is external.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) event(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		eventName := getJsString(r, f.Argument(0))
		properties := getJsStringMap(r, f.Argument(1))
		ts := &timestamppb.Timestamp{}
		if f.Argument(2) != goja.Undefined() && f.Argument(2) != goja.Null() {
			ts.Seconds = getJsInt(r, f.Argument(2))
		} else {
			ts.Seconds = time.Now().Unix()
		}
		external := false
		if f.Argument(3) != goja.Undefined() {
			external = getJsBool(r, f.Argument(3))
		}
		if n.eventFn != nil {
			n.eventFn(context.Background(), &api.Event{
				Name:       eventName,
				Properties: properties,
				Timestamp:  ts,
				External:   external,
			})
		}

		return goja.Undefined()
	}
}

// @group utils
// @summary Parses a CRON expression and a timestamp in UTC seconds, and returns the next matching timestamp in UTC seconds.
// @param expression(type=string) A valid CRON expression in standard format, for example "0 0 * * *" (meaning at midnight).
// @param timestamp(type=number) A time value expressed as UTC seconds.
// @return next_ts(number) The next UTC seconds timestamp (number) that matches the given CRON expression, and is immediately after the given timestamp.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) cronNext(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		cron := getJsString(r, f.Argument(0))
		ts := getJsInt(r, f.Argument(1))

		expr, err := cronexpr.Parse(cron)
		if err != nil {
			panic(r.NewTypeError("expects a valid cron string"))
		}

		t := time.Unix(ts, 0).UTC()
		next := expr.Next(t)
		nextTs := next.UTC().Unix()

		return r.ToValue(nextTs)
	}
}

// @group utils
// @summary Execute an arbitrary SQL query and return the number of rows affected. Typically an "INSERT", "DELETE", or "UPDATE" statement with no return columns.
// @param query(type=string) A SQL query to execute.
// @param parameters(type=any[]) Arbitrary parameters to pass to placeholders in the query.
// @return rowsAffected(number) A list of matches matching the parameters criteria.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) sqlExec(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		query := getJsString(r, f.Argument(0))
		var args []interface{}
		if f.Argument(1) == goja.Undefined() {
			args = make([]interface{}, 0)
		} else {
			var ok bool
			args, ok = f.Argument(1).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("expects array of query params"))
			}
		}

		var res sql.Result
		var err error
		err = database.ExecuteRetryable(func() error {
			res, err = n.db.Exec(query, args...)
			return err
		})
		if err != nil {
			n.logger.Error("Failed to exec db query.", zap.String("query", query), zap.Any("args", args), zap.Error(err))
			panic(r.NewGoError(fmt.Errorf("failed to exec db query: %s", err.Error())))
		}

		nRowsAffected, _ := res.RowsAffected()

		return r.ToValue(
			map[string]interface{}{
				"rowsAffected": nRowsAffected,
			},
		)
	}
}

// @group utils
// @summary Execute an arbitrary SQL query that is expected to return row data. Typically a "SELECT" statement.
// @param query(type=string) A SQL query to execute.
// @param parameters(type=any[]) Arbitrary parameters to pass to placeholders in the query.
// @return result(nkruntime.SqlQueryResult) An array of rows and the respective columns and values.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) sqlQuery(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		query := getJsString(r, f.Argument(0))
		var args []interface{}
		if f.Argument(1) == goja.Undefined() {
			args = make([]interface{}, 0)
		} else {
			var ok bool
			args, ok = f.Argument(1).Export().([]interface{})
			if !ok {
				panic(r.NewTypeError("expects array of query params"))
			}
		}

		var rows *sql.Rows
		var err error
		err = database.ExecuteRetryable(func() error {
			rows, err = n.db.Query(query, args...)
			return err
		})
		if err != nil {
			n.logger.Error("Failed to exec db query.", zap.String("query", query), zap.Any("args", args), zap.Error(err))
			panic(r.NewGoError(fmt.Errorf("failed to exec db query: %s", err.Error())))
		}
		defer rows.Close()

		rowColumns, err := rows.Columns()
		if err != nil {
			n.logger.Error("Failed to get row columns.", zap.Error(err))
			panic(r.NewGoError(fmt.Errorf("failed to get row columns: %s", err.Error())))
		}
		rowsColumnCount := len(rowColumns)
		resultRows := make([]*[]interface{}, 0)
		for rows.Next() {
			resultRowValues := make([]interface{}, rowsColumnCount)
			resultRowPointers := make([]interface{}, rowsColumnCount)
			for i := range resultRowValues {
				resultRowPointers[i] = &resultRowValues[i]
			}
			if err = rows.Scan(resultRowPointers...); err != nil {
				n.logger.Error("Failed to scan row results.", zap.Error(err))
				panic(r.NewGoError(fmt.Errorf("failed to scan row results: %s", err.Error())))
			}
			resultRows = append(resultRows, &resultRowValues)
		}
		if err = rows.Err(); err != nil {
			n.logger.Error("Failed scan rows.", zap.Error(err))
			panic(r.NewGoError(fmt.Errorf("failed to scan rows: %s", err.Error())))
		}

		results := make([]map[string]interface{}, 0, len(resultRows))
		for _, row := range resultRows {
			resultRow := make(map[string]interface{}, rowsColumnCount)
			for i, col := range rowColumns {
				resultRow[col] = (*row)[i]
			}
			results = append(results, resultRow)
		}

		return r.ToValue(results)
	}
}

// @group utils
// @summary Send a HTTP request that returns a data type containing the result of the HTTP response.
// @param url(type=string) The URL of the web resource to request.
// @param method(type=string) The HTTP method verb used with the request.
// @param headers(type=string) A table of headers used with the request.
// @param content(type=string) The bytes to send with the request.
// @param timeout(type=number, optional=true, default=5000) Timeout of the request in milliseconds.
// @return returnVal(nkruntime.httpResponse) Code, Headers, and Body response values for the HTTP response.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) httpRequest(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		url := getJsString(r, f.Argument(0))
		method := strings.ToUpper(getJsString(r, f.Argument(1)))

		headers := make(map[string]string)
		if !goja.IsUndefined(f.Argument(2)) && !goja.IsNull(f.Argument(2)) {
			headers = getJsStringMap(r, f.Argument(2))
		}

		var body string
		if !goja.IsUndefined(f.Argument(3)) && !goja.IsNull(f.Argument(3)) {
			body = getJsString(r, f.Argument(3))
		}

		timeoutArg := f.Argument(4)
		if timeoutArg != goja.Undefined() && timeoutArg != goja.Null() {
			n.httpClient.Timeout = time.Duration(timeoutArg.ToInteger()) * time.Millisecond
		}

		n.logger.Debug(fmt.Sprintf("Http Timeout: %v", n.httpClient.Timeout))

		if url == "" {
			panic(r.NewTypeError("URL string cannot be empty."))
		}

		if !(method == "GET" || method == "POST" || method == "PUT" || method == "PATCH") {
			panic(r.NewTypeError("Invalid method must be one of: 'get', 'post', 'put', 'patch'."))
		}

		var requestBody io.Reader
		if body != "" {
			requestBody = strings.NewReader(body)
		}

		req, err := http.NewRequest(method, url, requestBody)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("HTTP request is invalid: %v", err.Error())))
		}

		for h, v := range headers {
			// TODO accept multiple values
			req.Header.Add(h, v)
		}

		resp, err := n.httpClient.Do(req)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("HTTP request error: %v", err.Error())))
		}

		// Read the response body.
		responseBody, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("HTTP response body error: %v", err.Error())))
		}
		respHeaders := make(map[string][]string, len(resp.Header))
		for h, v := range resp.Header {
			respHeaders[h] = v
		}

		returnVal := map[string]interface{}{
			"code":    resp.StatusCode,
			"headers": respHeaders,
			"body":    string(responseBody),
		}

		return r.ToValue(returnVal)
	}
}

// @group utils
// @summary Base64 encode a string input.
// @param input(type=string) The string which will be base64 encoded.
// @return out(string) Encoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) base64Encode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getJsString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getJsBool(r, f.Argument(1))
		}

		e := base64.URLEncoding
		if !padding {
			e = base64.RawURLEncoding
		}

		out := e.EncodeToString([]byte(in))
		return r.ToValue(out)
	}
}

// @group utils
// @summary Decode a base64 encoded string.
// @param input(type=string) The string which will be base64 decoded.
// @return out(string) Decoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) base64Decode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getJsString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getJsBool(r, f.Argument(1))
		}

		if !padding {
			// Pad string up to length multiple of 4 if needed to effectively make padding optional.
			if maybePad := len(in) % 4; maybePad != 0 {
				in += strings.Repeat("=", 4-maybePad)
			}
		}

		out, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("Failed to decode string: %s", in)))
		}
		return r.ToValue(string(out))
	}
}

// @group utils
// @summary Base64 URL encode a string input.
// @param input(type=string) The string which will be base64 URL encoded.
// @return out(string) Encoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) base64UrlEncode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getJsString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getJsBool(r, f.Argument(1))
		}

		e := base64.URLEncoding
		if !padding {
			e = base64.RawURLEncoding
		}

		out := e.EncodeToString([]byte(in))
		return r.ToValue(out)
	}
}

// @group utils
// @summary Decode a base64 URL encoded string.
// @param input(type=string) The string to be decoded.
// @return out(string) Decoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) base64UrlDecode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getJsString(r, f.Argument(0))
		padding := true
		if f.Argument(1) != goja.Undefined() {
			padding = getJsBool(r, f.Argument(1))
		}

		if !padding {
			// Pad string up to length multiple of 4 if needed to effectively make padding optional.
			if maybePad := len(in) % 4; maybePad != 0 {
				in += strings.Repeat("=", 4-maybePad)
			}
		}

		out, err := base64.URLEncoding.DecodeString(in)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("Failed to decode string: %s", in)))
		}
		return r.ToValue(string(out))
	}
}

// @group utils
// @summary base16 encode a string input.
// @param input(type=string) The string to be encoded.
// @return out(string) Encoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) base16Encode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getJsString(r, f.Argument(0))

		out := hex.EncodeToString([]byte(in))
		return r.ToValue(out)
	}
}

// @group utils
// @summary Decode a base16 encoded string.
// @param input(type=string) The string to be decoded.
// @return out(string) Decoded string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) base16Decode(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		in := getJsString(r, f.Argument(0))

		out, err := hex.DecodeString(in)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("Failed to decode string: %s", in)))
		}
		return r.ToValue(string(out))
	}
}

// @group utils
// @summary Generate a JSON Web Token.
// @param signingMethod(type=string) The signing method to be used, either HS256 or RS256.
// @param claims(type=[]string) The JWT payload.
// @return signedToken(string) The newly generated JWT.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) jwtGenerate(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		algoType := getJsString(r, f.Argument(0))

		var signingMethod jwt.SigningMethod
		switch algoType {
		case "HS256":
			signingMethod = jwt.SigningMethodHS256
		case "RS256":
			signingMethod = jwt.SigningMethodRS256
		default:
			panic(r.NewTypeError("unsupported algo type - only allowed 'HS256', 'RS256'."))
		}

		signingKey := getJsString(r, f.Argument(1))
		if signingKey == "" {
			panic(r.NewTypeError("signing key cannot be empty"))
		}

		if f.Argument(1) == goja.Undefined() {
			panic(r.NewTypeError("claims argument is required"))
		}

		claims, ok := f.Argument(2).Export().(map[string]interface{})
		if !ok {
			panic(r.NewTypeError("claims must be an object"))
		}
		jwtClaims := jwt.MapClaims{}
		for k, v := range claims {
			jwtClaims[k] = v
		}

		var pk interface{}
		switch signingMethod {
		case jwt.SigningMethodRS256:
			block, _ := pem.Decode([]byte(signingKey))
			if block == nil {
				panic(r.NewGoError(errors.New("could not parse private key: no valid blocks found")))
			}

			var err error
			pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				panic(r.NewGoError(fmt.Errorf("could not parse private key: %v", err.Error())))
			}
		case jwt.SigningMethodHS256:
			pk = []byte(signingKey)
		}

		token := jwt.NewWithClaims(signingMethod, jwtClaims)
		signedToken, err := token.SignedString(pk)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("failed to sign token: %v", err.Error())))
		}

		return r.ToValue(signedToken)
	}
}

// @group utils
// @summary aes128 encrypt a string input.
// @param input(type=string) The string which will be aes128 encrypted.
// @param key(type=string) The 16 Byte encryption key.
// @return cipherText(string) The ciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) aes128Encrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		key := getJsString(r, f.Argument(1))

		cipherText, err := n.aesEncrypt(16, input, key)
		if err != nil {
			panic(r.NewGoError(err))
		}

		return r.ToValue(cipherText)
	}
}

// @group utils
// @summary Decrypt an aes128 encrypted string.
// @param input(type=string) The string to be decrypted.
// @param key(type=string) The 16 Byte decryption key.
// @return clearText(string) The deciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) aes128Decrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		key := getJsString(r, f.Argument(1))

		clearText, err := n.aesDecrypt(16, input, key)
		if err != nil {
			panic(r.NewGoError(err))
		}

		return r.ToValue(clearText)
	}
}

// @group utils
// @summary aes256 encrypt a string input.
// @param input(type=string) The string which will be aes256 encrypted.
// @param key(type=string) The 32 Byte encryption key.
// @return cipherText(string) The ciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) aes256Encrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		key := getJsString(r, f.Argument(1))

		cipherText, err := n.aesEncrypt(32, input, key)
		if err != nil {
			panic(r.NewGoError(err))
		}

		return r.ToValue(cipherText)
	}
}

// @group utils
// @summary Decrypt an aes256 encrypted string.
// @param input(type=string) The string to be decrypted.
// @param key(type=string) The 32 Byte decryption key.
// @return clearText(string) The deciphered input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) aes256Decrypt(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		key := getJsString(r, f.Argument(1))

		clearText, err := n.aesDecrypt(32, input, key)
		if err != nil {
			panic(r.NewGoError(err))
		}

		return r.ToValue(clearText)
	}
}

// @group utils
// @summary aes encrypt a string input and return the cipher text base64 encoded.
// @param keySize(type=int) The size in bytes of the encryption key.
// @param input(type=string) The string which will be encrypted.
// @param key(type=string) The encryption key.
// @return cipherText(string) The ciphered and base64 encoded input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) aesEncrypt(keySize int, input, key string) (string, error) {
	if len(key) != keySize {
		return "", errors.New(fmt.Sprintf("expects key %v bytes long", keySize))
	}

	// Pad string up to length multiple of 4 if needed.
	if maybePad := len(input) % 4; maybePad != 0 {
		input += strings.Repeat(" ", 4-maybePad)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.New(fmt.Sprintf("error creating cipher block: %v", err.Error()))
	}

	cipherText := make([]byte, aes.BlockSize+len(input))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", errors.New(fmt.Sprintf("error getting iv: %v", err.Error()))
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(input))

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// @group utils
// @summary aes decrypt a base 64 encoded string input.
// @param keySize(type=int) The size in bytes of the decryption key.
// @param input(type=string) The string which will be decrypted.
// @param key(type=string) The encryption key.
// @return clearText(string) The deciphered and decoded input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) aesDecrypt(keySize int, input, key string) (string, error) {
	if len(key) != keySize {
		return "", errors.New(fmt.Sprintf("expects key %v bytes long", keySize))
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.New(fmt.Sprintf("error creating cipher block: %v", err.Error()))
	}

	decodedtText, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", errors.New(fmt.Sprintf("error decoding cipher text: %v", err.Error()))
	}
	cipherText := decodedtText
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

// @group utils
// @summary Create an md5 hash from the input.
// @param input(type=string) The input string to hash.
// @return hash(string) A string with the md5 hash of the input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) md5Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))

		hash := fmt.Sprintf("%x", md5.Sum([]byte(input)))

		return r.ToValue(hash)
	}
}

// @group utils
// @summary Create an SHA256 hash from the input.
// @param input(type=string) The input string to hash.
// @return hash(string) A string with the SHA256 hash of the input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) sha256Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))

		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(input)))

		return r.ToValue(hash)
	}
}

// @group utils
// @summary Create a RSA encrypted SHA256 hash from the input.
// @param input(type=string) The input string to hash.
// @param key(type=string) The RSA private key.
// @return signature(string) A string with the RSA encrypted SHA256 hash of the input.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) rsaSHA256Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		key := getJsString(r, f.Argument(1))
		if key == "" {
			panic(r.NewTypeError("key cannot be empty"))
		}

		block, _ := pem.Decode([]byte(key))
		if block == nil {
			panic(r.NewGoError(errors.New("could not parse private key: no valid blocks found")))
		}
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("error parsing key: %v", err.Error())))
		}

		hashed := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("error signing input: %v", err.Error())))
		}

		return r.ToValue(string(signature))
	}
}

// @group utils
// @summary Create a HMAC-SHA256 hash from input and key.
// @param input(type=string) The input string to hash.
// @param key(type=string) The hashing key.
// @return mac(string) Hashed input as a string using the key.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) hmacSHA256Hash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		key := getJsString(r, f.Argument(1))
		if key == "" {
			panic(r.NewTypeError("key cannot be empty"))
		}

		mac := hmac.New(sha256.New, []byte(key))
		_, err := mac.Write([]byte(input))
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("error creating hash: %v", err.Error())))
		}

		return r.ToValue(string(mac.Sum(nil)))
	}
}

// @group utils
// @summary Generate one-way hashed string using bcrypt.
// @param input(type=string) The input string to bcrypt.
// @return hash(string) Hashed string.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) bcryptHash(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		input := getJsString(r, f.Argument(0))
		hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
		if err != nil {
			panic(r.NewGoError(fmt.Errorf("error hashing input: %v", err.Error())))
		}

		return r.ToValue(string(hash))
	}
}

// @group utils
// @summary Compare hashed input against a plaintext input.
// @param input(type=string) The bcrypted input string.
// @param plaintext(type=string) Plaintext input to compare against.
// @return result(bool) True if they are the same, false otherwise.
// @return error(error) An optional error value if an error occurred.
func (n *RuntimeJavascriptLinnaModule) bcryptCompare(r *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(f goja.FunctionCall) goja.Value {
		hash := getJsString(r, f.Argument(0))
		if hash == "" {
			panic(r.NewTypeError("hash cannot be empty"))
		}

		plaintext := getJsString(r, f.Argument(1))
		if plaintext == "" {
			panic(r.NewTypeError("plaintext cannot be empty"))
		}

		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
		if err == nil {
			return r.ToValue(true)
		} else if err == bcrypt.ErrHashTooShort || err == bcrypt.ErrMismatchedHashAndPassword {
			return r.ToValue(false)
		}

		panic(r.NewGoError(fmt.Errorf("error comparing hash and plaintext: %v", err.Error())))
	}
}

func NewRuntimeJavascriptLinnaModule(c *RuntimeJavascriptLinnaModuleConfiguration) *RuntimeJavascriptLinnaModule {
	return &RuntimeJavascriptLinnaModule{
		logger:               c.Logger,
		db:                   c.DB,
		protojsonMarshaler:   c.ProtojsonMarshaler,
		protojsonUnmarshaler: c.ProtojsonUnmarshaler,
		config:               c.Config,
		localCache:           NewRuntimeJavascriptLocalCache(),
		node:                 c.Node,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		eventFn: c.eventFn,
	}
}

func getJsString(r *goja.Runtime, v goja.Value) string {
	s, ok := v.Export().(string)
	if !ok {
		panic(r.NewTypeError("expects string"))
	}
	return s
}

func getJsStringMap(r *goja.Runtime, v goja.Value) map[string]string {
	m, ok := v.Export().(map[string]interface{})
	if !ok {
		panic(r.NewTypeError("expects object with string keys and values"))
	}

	res := make(map[string]string)
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			panic(r.NewTypeError("expects string"))
		}
		res[k] = s
	}
	return res
}

func getJsInt(r *goja.Runtime, v goja.Value) int64 {
	i, ok := v.Export().(int64)
	if !ok {
		panic(r.NewTypeError("expects number"))
	}
	return i
}

func getJsFloat(r *goja.Runtime, v goja.Value) float64 {
	e := v.Export()
	f, ok := e.(float64)
	if !ok {
		i, ok := e.(int64)
		if ok {
			return float64(i)
		} else {
			panic(r.NewTypeError("expects number"))
		}
	}
	return f
}

func getJsBool(r *goja.Runtime, v goja.Value) bool {
	b, ok := v.Export().(bool)
	if !ok {
		panic(r.NewTypeError("expects boolean"))
	}
	return b
}

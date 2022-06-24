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

package types

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
)

// 自定义数字类型,解决前端JS无法处理int64的问题
type Bigint string

func (bigint *Bigint) Scan(value interface{}) error {
	switch v := value.(type) {
	case int:
		*bigint = Bigint(strconv.FormatInt(int64(v), 10))
	case int8:
		*bigint = Bigint(strconv.FormatInt(int64(v), 10))
	case int16:
		*bigint = Bigint(strconv.FormatInt(int64(v), 10))
	case int32:
		*bigint = Bigint(strconv.FormatInt(int64(v), 10))
	case int64:
		*bigint = Bigint(strconv.FormatInt(int64(v), 10))
	case uint:
		*bigint = Bigint(strconv.FormatUint(uint64(v), 10))
	case uint8:
		*bigint = Bigint(strconv.FormatUint(uint64(v), 10))
	case uint16:
		*bigint = Bigint(strconv.FormatUint(uint64(v), 10))
	case uint32:
		*bigint = Bigint(strconv.FormatUint(uint64(v), 10))
	case uint64:
		*bigint = Bigint(strconv.FormatUint(uint64(v), 10))
	default:
		return errors.New(fmt.Sprint("Failed to bigint value:", value))
	}
	return nil
}

func (bigint Bigint) Value() (driver.Value, error) {
	return strconv.ParseUint(bigint.String(), 10, 64)
}

func (bigint Bigint) Int64() (int64, error) {
	return strconv.ParseInt(bigint.String(), 10, 64)
}

func (bigint Bigint) Uint64() (uint64, error) {
	return strconv.ParseUint(bigint.String(), 10, 64)
}

func (bigint Bigint) String() string {
	return string(bigint)
}

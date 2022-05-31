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
// Author: Randyma
// Date: 2022-05-31 23:50:04
// LastEditors: Randyma
// LastEditTime: 2022-05-31 23:50:11
// Description: 请求加密验证

package token

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"sort"
	"strings"
)

// TKS 签名
type TKS []string

func (t TKS) Len() int { return len(t) }

func (t TKS) Less(i, j int) bool { return t[i] > t[j] }

func (t TKS) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

func (t *TKS) Push(s ...string) {
	*t = append(*t, s...)
	sort.Sort(*t)
}

func (t TKS) Marshal(key string) string {
	s := strings.Join(t, "&")
	mac := hmac.New(sha1.New, []byte(key+"&"))
	mac.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func NewTKS() TKS {
	return make(TKS, 0)
}

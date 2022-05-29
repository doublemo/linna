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
// Date: 2022-05-29 22:38:20
// LastEditors: Randyma
// LastEditTime: 2022-05-29 22:38:32
// Description: 服务发现，节点信息处理

package sd

import (
	"net/url"
)

//Endpoint 节点信息接口
type Endpoint interface {
	ID() string             // 节点唯一识别码
	Name() string           // 节点服务名称
	Addr() string           // 节点地址
	Set(k, v string)        // 设置节点存值
	Get(k string) string    // 获取节点存值
	Delete(k string)        // 删除节点信息
	Marshal() string        // 节点信息编码
	Unmarshal(string) error // 节点信息解码
}

// EndpointLocal 实现本地节点
type EndpointLocal struct {
	id     string
	name   string
	addr   string
	values url.Values
}

func (endpoint EndpointLocal) ID() string {
	return endpoint.id
}

func (endpoint EndpointLocal) Name() string {
	return endpoint.name
}

func (endpoint EndpointLocal) Addr() string {
	return endpoint.addr
}

func (endpoint *EndpointLocal) Delete(k string) {
	endpoint.values.Del(k)
}

func (endpoint *EndpointLocal) Set(k, v string) {
	endpoint.values.Set(k, v)
}

func (endpoint *EndpointLocal) Get(k string) string {
	return endpoint.values.Get(k)
}

func (endpoint *EndpointLocal) Marshal() string {
	endpoint.Set("id", endpoint.id)
	endpoint.Set("name", endpoint.name)
	endpoint.Set("addr", endpoint.addr)
	return endpoint.values.Encode()
}

func (endpoint *EndpointLocal) Unmarshal(data string) error {
	values, err := url.ParseQuery(data)
	if err != nil {
		return err
	}

	newValues := make(url.Values)
	for k, v := range values {
		if len(v) < 1 {
			continue
		}
		switch k {
		case "id":
			endpoint.id = v[0]
		case "name":
			endpoint.name = v[0]
		case "addr":
			endpoint.addr = v[0]
		default:
			newValues.Set(k, v[0])
		}
	}

	endpoint.values = newValues
	return nil
}

func NewEndpoint(id, name, addr string) *EndpointLocal {
	return &EndpointLocal{
		id:     id,
		name:   name,
		addr:   addr,
		values: make(url.Values),
	}
}

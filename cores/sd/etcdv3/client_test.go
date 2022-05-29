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
// Date: 2022-05-29 23:46:54
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:47:10
// Description:

package etcdv3

import (
	"context"
	"testing"
	"time"

	"github.com/doublemo/linna/cores/sd"
	"google.golang.org/grpc"
)

const addr string = "127.0.0.1:2379"

func TestNewClientLocal(t *testing.T) {
	c := Config{
		Addrs:         []string{addr},
		DialTimeout:   3 * time.Second,
		DialKeepAlive: 3 * time.Second,
		DialOptions:   []grpc.DialOption{grpc.WithBlock()},
	}
	client, err := NewClient(context.Background(), c)
	if err != nil {
		t.Fatal(err)
		return
	}

	client.Register(Service{Prefix: "/services/baa/xx", Endpoint: sd.NewEndpoint("test01", "test", "")})
	t.Log(client.GetEntries("/services/baa"))

	ch := make(chan struct{})
	go client.WatchPrefix("/services/baa", ch)

	<-ch
	t.Log(client.GetEntries("/services/baa"))
	t.Log("ddd----")
	//select {}
}

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
// Date: 2022-05-12 09:58:12
// LastEditors: randyma
// LastEditTime: 2022-05-12 10:37:34
// Description: 节点处理

package endpoint

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/doublemo/linna/cores/sd"
	"github.com/doublemo/linna/cores/sd/etcdv3"
	"github.com/rcrowley/go-metrics"
	"github.com/rpcxio/rpcx-etcd/serverplugin"
	"google.golang.org/grpc"
)

var (
	endpoint   sd.Endpoint
	endpointer sd.Endpointer
	instancer  sd.Instancer
	client     etcdv3.Client
	prefix     string
)

var (
	ErrEndpointNil = errors.New("endpoint is nil")
)

// Configuration 配置文件
type Configuration struct {
	ID     string            `yaml:"id" json:"id" usage:"节点唯一编号"`
	Name   string            `yaml:"name" json:"name" usage:"节点唯一名称"`
	Etcd   EctdConfiguration `yaml:"etcd" json:"etcd" usage:"集群etcd"`
	Group  string            `yaml:"group" json:"group" usage:"集群分组"`
	Weight int               `yaml:"weight" json:"weight" usage:"集群中比重"`
	IP     string            `yaml:"ip" json:"ip" usage:"本地IP"`
	Domain string            `yaml:"domain" json:"domain" usage:"域名"`
}

type EctdConfiguration struct {
	Addr          []string `yaml:"addr" json:"addr" usage:"etcd集群地址"`
	Path          string   `yaml:"path" json:"path" usage:"服务前缀"`
	DialTimeout   int      `yaml:"dial_timeout" json:"dial_timeout" usage:"etcd超时"`
	DialKeepAlive int      `yaml:"dial_keep_alive" json:"dial_keep_alive" usage:"etcd存活时间"`
}

func (etcd *EctdConfiguration) RpcxRegisterPlugin(addr string) (*serverplugin.EtcdV3RegisterPlugin, error) {
	r := &serverplugin.EtcdV3RegisterPlugin{
		ServiceAddress: addr,
		EtcdServers:    etcd.Addr,
		BasePath:       etcd.Path,
		Metrics:        metrics.NewRegistry(),
		UpdateInterval: time.Minute,
	}

	if err := r.Start(); err != nil {
		return nil, err
	}

	return r, nil
}

func NewConfiguration() Configuration {
	return Configuration{
		ID:   "linna-node-1",
		Name: "Linna",
		Etcd: NewEctdConfiguration(),
	}
}

func NewEctdConfiguration() EctdConfiguration {
	return EctdConfiguration{
		Addr:          []string{"127.0.0.1:2379"},
		Path:          "/linna/services",
		DialTimeout:   3,
		DialKeepAlive: 3,
	}
}

func Initializer(ctx context.Context, c Configuration) (err error) {
	client, err = etcdv3.NewClient(ctx, etcdv3.Config{
		Addrs:         c.Etcd.Addr,
		DialTimeout:   time.Duration(c.Etcd.DialTimeout) * time.Second,
		DialKeepAlive: time.Duration(c.Etcd.DialKeepAlive) * time.Second,
		DialOptions:   []grpc.DialOption{grpc.WithBlock()},
	})

	if err != nil {
		return
	}

	instancer, err = etcdv3.NewInstancer(client, c.Etcd.Path)
	if err != nil {
		return
	}

	prefix = c.Etcd.Path
	endpointer = sd.NewEndpointer(instancer, sd.InvalidateOnError(time.Second))
	endpoint = sd.NewEndpoint(c.ID, c.Name, "")
	endpoint.Set("weight", strconv.Itoa(c.Weight))
	endpoint.Set("group", c.Group)
	endpoint.Set("domain", c.Domain)
	endpoint.Set("ip", c.IP)
	return nil
}

func JoinCluster() sd.Registrar {
	return etcdv3.NewRegistrar(client, etcdv3.Service{Prefix: prefix, Endpoint: endpoint})
}

func Endpoint() sd.Endpoint {
	return endpoint
}

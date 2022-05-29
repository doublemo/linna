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
// Date: 2022-05-29 23:45:22
// LastEditors: Randyma
// LastEditTime: 2022-05-29 23:45:41
// Description:

package etcdv3

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
)

var (
	// ErrNoKey indicates a client method needs a key but receives none.
	ErrNoKey = errors.New("no key provided")

	// ErrNoValue indicates a client method needs a value but receives none.
	ErrNoValue = errors.New("no value provided")
)

type (
	// Config etcdv3 client
	Config struct {
		Addrs         []string
		Cert          string
		Key           string
		CACert        string
		DialTimeout   time.Duration
		DialKeepAlive time.Duration

		DialOptions []grpc.DialOption

		Username string
		Password string
	}

	// Client is a wrapper around the etcd client.
	Client interface {
		// GetEntries queries the given prefix in etcd and returns a slice
		// containing the values of all keys found, recursively, underneath that
		// prefix.
		GetEntries(prefix string) ([]string, error)

		// WatchPrefix watches the given prefix in etcd for changes. When a change
		// is detected, it will signal on the passed channel. Clients are expected
		// to call GetEntries to update themselves with the latest set of complete
		// values. WatchPrefix will always send an initial sentinel value on the
		// channel after establishing the watch, to ensure that clients always
		// receive the latest set of values. WatchPrefix will block until the
		// context passed to the NewClient constructor is terminated.
		WatchPrefix(prefix string, ch chan struct{})

		// Register a service with etcd.
		Register(s Service) error

		// Deregister a service with etcd.
		Deregister(s Service) error

		// LeaseID returns the lease id created for this service instance
		LeaseID() int64
	}

	// ClientLocal etcd client v3
	ClientLocal struct {
		cli     *clientv3.Client
		ctx     context.Context
		kv      clientv3.KV
		watcher clientv3.Watcher
		wctx    context.Context
		wcf     context.CancelFunc
		leaseID clientv3.LeaseID
		hbch    <-chan *clientv3.LeaseKeepAliveResponse
		leaser  clientv3.Lease
	}
)

// GetEntries implements the etcd Client interface.
func (c *ClientLocal) GetEntries(key string) ([]string, error) {
	resp, err := c.kv.Get(c.ctx, key, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	entries := make([]string, len(resp.Kvs))
	for i, kv := range resp.Kvs {
		entries[i] = string(kv.Value)
	}

	return entries, nil
}

// WatchPrefix implements the etcd Client interface.
func (c *ClientLocal) WatchPrefix(prefix string, ch chan struct{}) {
	c.wctx, c.wcf = context.WithCancel(c.ctx)
	c.watcher = clientv3.NewWatcher(c.cli)
	wch := c.watcher.Watch(c.wctx, prefix, clientv3.WithPrefix(), clientv3.WithRev(0))
	ch <- struct{}{}
	for wr := range wch {
		if wr.Canceled {
			return
		}
		ch <- struct{}{}
	}
}

func (c *ClientLocal) Register(s Service) error {
	if s.Key() == "" {
		return ErrNoKey
	}

	if s.Value() == "" {
		return ErrNoValue
	}

	if c.leaser != nil {
		c.leaser.Close()
	}

	c.leaser = clientv3.NewLease(c.cli)

	if c.watcher == nil {
		c.watcher = clientv3.NewWatcher(c.cli)
	}

	if c.kv == nil {
		c.kv = clientv3.NewKV(c.cli)
	}

	if s.TTL == nil {
		s.TTL = NewTTLOption(time.Second*3, time.Second*100)
	}

	grantResp, err := c.leaser.Grant(c.ctx, int64(s.TTL.ttl.Seconds()))
	if err != nil {
		return err
	}

	c.leaseID = grantResp.ID
	_, err = c.kv.Put(c.ctx, s.Key(), s.Value(), clientv3.WithLease(c.leaseID))
	if err != nil {
		return err
	}

	// this will keep the key alive 'forever' or until we revoke it or
	// the context is canceled
	c.hbch, err = c.leaser.KeepAlive(c.ctx, c.leaseID)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case r := <-c.hbch:
				// avoid dead loop when channel was closed
				if r == nil {
					return
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (c *ClientLocal) Deregister(s Service) error {
	defer c.close()
	if s.Key() == "" {
		return ErrNoKey
	}
	if _, err := c.cli.Delete(c.ctx, s.Key(), clientv3.WithIgnoreLease()); err != nil {
		return err
	}

	return nil
}

// close will close any open clients and call
// the watcher cancel func
func (c *ClientLocal) close() {
	if c.leaser != nil {
		c.leaser.Close()
	}
	if c.watcher != nil {
		c.watcher.Close()
	}
	if c.wcf != nil {
		c.wcf()
	}
}

func (c *ClientLocal) LeaseID() int64 {
	return int64(c.leaseID)
}

// NewClient returns Client with a connection to the named machines. It will
// return an error if a connection to the cluster cannot be made.
func NewClient(ctx context.Context, config Config) (*ClientLocal, error) {
	if config.DialTimeout == 0 {
		config.DialTimeout = 3 * time.Second
	}

	if config.DialKeepAlive == 0 {
		config.DialKeepAlive = 3 * time.Second
	}

	var (
		err    error
		tlscfg *tls.Config
	)

	if config.Cert != "" && config.Key != "" {
		tlsInfo := transport.TLSInfo{
			CertFile:      config.Cert,
			KeyFile:       config.Key,
			TrustedCAFile: config.CACert,
		}

		tlscfg, err = tlsInfo.ClientConfig()
		if err != nil {
			return nil, err
		}
	}

	cli, err := clientv3.New(clientv3.Config{
		Context:           ctx,
		Endpoints:         config.Addrs,
		DialTimeout:       config.DialTimeout,
		DialKeepAliveTime: config.DialKeepAlive,
		DialOptions:       config.DialOptions,
		TLS:               tlscfg,
		Username:          config.Username,
		Password:          config.Password,
	})

	if err != nil {
		return nil, err
	}
	return &ClientLocal{cli: cli, ctx: ctx, kv: clientv3.NewKV(cli)}, nil
}

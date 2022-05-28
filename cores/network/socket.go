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
// Date: 2022-05-28 23:19:32
// LastEditors: Randyma
// LastEditTime: 2022-05-28 23:19:54
// Description:

package network

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
)

// Socket tcp网络处理
type Socket struct {
	lis       *net.TCPListener
	onConnect atomic.Value
	onClose   atomic.Value
	stopOnce  sync.Once
	mutexRW   sync.RWMutex
	cancelFn  context.CancelFunc
}

func (s *Socket) OnConnect(f func(context.Context, net.Conn)) {
	s.onConnect.Store(f)
}

func (s *Socket) OnClose(f func()) {
	s.onClose.Store(f)
}

func (s *Socket) Serve(addr string, readBufferSize, writeBufferSize int) error {
	defer func() {
		if onClose, ok := s.onClose.Load().(func()); ok && onClose != nil {
			onClose()
		}
	}()

	if err := s.listenTo(addr); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFn = cancel
	connChan := make(chan *net.TCPConn, 128)
	done := make(chan error)
	go func(ctxf context.Context, c chan *net.TCPConn, ok chan error) {
		defer close(c)
		ok <- s.accept(ctxf, c)
	}(ctx, connChan, done)

	for {
		select {
		case conn, ok := <-connChan:
			if !ok {
				return nil
			}

			conn.SetReadBuffer(readBufferSize)
			conn.SetWriteBuffer(writeBufferSize)
			if handler, ok := s.onConnect.Load().(func(context.Context, net.Conn)); ok && handler != nil {
				handler(ctx, conn)
			}

		case err := <-done:
			return err

		case <-ctx.Done():
			return nil
		}
	}

}

func (s *Socket) accept(ctx context.Context, connChan chan *net.TCPConn) error {
	s.mutexRW.RLock()
	lis := s.lis
	s.mutexRW.RUnlock()

	for {
		conn, err := lis.AcceptTCP()
		if err != nil {
			return err
		}

		select {
		case connChan <- conn:
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Socket) listenTo(addr string) error {
	resolveAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	if lis, err := net.ListenTCP("tcp", resolveAddr); err != nil {
		return err
	} else {
		s.mutexRW.Lock()
		s.lis = lis
		s.mutexRW.Unlock()
	}

	return nil
}

func (s *Socket) Close() {
	s.stopOnce.Do(func() {
		s.cancelFn()
		s.mutexRW.RLock()
		lis := s.lis
		s.mutexRW.RUnlock()
		if lis != nil {
			lis.Close()
		}
	})
}

func NewSocket() *Socket {
	return &Socket{}
}

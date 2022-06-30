package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/doublemo/linna/cores/endpoint"
	"github.com/doublemo/linna/cores/sd"
	"github.com/doublemo/linna/cores/sd/etcdv3"
	"github.com/doublemo/linna/cores/sd/lb"
	"go.uber.org/zap"
)



type Cluster struct {
	config       Configuration
	client       etcdv3.Client
	logger       *zap.Logger
	node         Node
	nodes        atomic.Value
	subnodes     atomic.Value
	services     atomic.Value
	instancer    sd.Instancer
	subinstancer sd.Instancer
	endpoint     *sd.SoildStateEndpointer
	registrar    sd.Registrar
	cancelFn     context.CancelFunc
	once         sync.Once
}

func (s *Cluster) Endpoints() ([]endpoint.Endpoint, error) {
	return s.endpoint.Endpoints()
}

func (s *Cluster) Nodes() []Node {
	rows := s.nodes.Load().(map[string]Node)
	nodes := make([]Node, len(rows))
	for _, row := range rows {
		nodes = append(nodes, row)
	}
	return nodes
}

func (s *Cluster) Node(id string) (Node, bool) {
	rows := s.nodes.Load().(map[string]Node)
	node, ok := rows[id]
	return node, ok
}

func (s *Cluster) Local() Node {
	return s.node
}

func (s *Cluster) Services() []Node {
	rows := s.subnodes.Load().(map[string]Node)
	nodes := make([]Node, len(rows))
	for _, row := range rows {
		nodes = append(nodes, row)
	}
	return nodes
}

func (s *Cluster) ServiceEndpoints(name string) ([]endpoint.Endpoint, error) {
	data := s.services.Load().(map[string]*sd.SoildStateEndpointer)
	if m, ok := data[name]; ok {
		return m.Endpoints()
	}

	return nil, errors.New("not found")
}

func (s *Cluster) serve(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	ticker := time.NewTicker(time.Second)
	event := make(chan sd.Event, 1)
	eventSub := make(chan sd.Event, 1)
	s.instancer.Register(event)
	s.subinstancer.Register(eventSub)
	defer func() {
		s.subinstancer.Deregister(eventSub)
		s.instancer.Deregister(event)
		s.registrar.Deregister()
		ticker.Stop()
		s.logger.Info("cluster shutdown")
	}()

	for {
		select {
		case evt := <-event:
			if evt.Err != nil {
				s.logger.Warn("event error", zap.Error(evt.Err))
				continue
			}

			nodes, _ := s.convertNodes(evt.Instances...)
			s.nodes.Store(nodes)
			s.endpoint.Update(evt)

		case evt := <-eventSub:
			if evt.Err != nil {
				s.logger.Warn("sub event error", zap.Error(evt.Err))
				continue
			}

			nodes, services := s.convertNodes(evt.Instances...)
			s.subnodes.Store(nodes)
			s.services.Store(services)

		case <-ticker.C:
			l := lb.NewRandom(s.endpoint, time.Now().UnixNano())
			fn, err := l.Endpoint()
			if err != nil {
				fmt.Println("----d--", err)
			}

			fmt.Println(fn(context.Background(), "testes---"))

		case <-ctx.Done():
			return
		}
	}
}

func (s *Cluster) convertNodes(instances ...string) (map[string]Node, map[string]*sd.SoildStateEndpointer) {
	nodes := make(map[string]Node)
	services := make(map[string][]string)
	for _, instance := range instances {
		node := &NodeLocal{}
		if err := node.Unmarshal(instance); err != nil {
			s.logger.Error("node unmarshal failed", zap.Error(err), zap.String("instance", instance))
			continue
		}
		nodes[node.ID()] = node
		if _, ok := services[node.Name]; !ok {
			services[node.Name] = make([]string, 0)
		}
		services[node.Name] = append(services[node.Name], instance)
	}

	endpointers := make(map[string]*sd.SoildStateEndpointer, len(services))
	for k, v := range services {
		endpointer := sd.NewSoildStateEndpointer(s.factory, s.logger, sd.InvalidateOnError(time.Second))
		endpointer.Update(sd.Event{Instances: v})
		endpointers[k] = endpointer
	}

	return nodes, endpointers
}

func (s *Cluster) listen() (err error) {
	key := JoinServiceName(s.config.Prefix, s.config.Name)
	subkey := JoinServiceName(s.config.Prefix, "sub_"+s.config.Name)
	nodeInfo, err := s.node.Marshal()
	if err != nil {
		s.logger.Error("Node marshal failed", zap.Error(err))
		return err
	}

	service := etcdv3.Service{
		Key:   JoinServiceName(key, s.node.ID()),
		Value: nodeInfo,
		TTL:   etcdv3.NewTTLOption(time.Second*3, time.Second*10),
	}

	if s.node.Sub() {
		service.Key = JoinServiceName(subkey, s.node.ID())
	}

	s.registrar = etcdv3.NewRegistrar(s.client, service, s.logger)
	s.registrar.Register()

	s.instancer, err = etcdv3.NewInstancer(s.client, key, s.logger)
	if err != nil {
		s.logger.Error("Cluster instancer failed", zap.Error(err))
		return
	}

	s.subinstancer, err = etcdv3.NewInstancer(s.client, subkey, s.logger)
	if err != nil {
		s.logger.Error("Sub cluster instancer failed", zap.Error(err))
		return
	}

	s.endpoint = sd.NewSoildStateEndpointer(s.factory, s.logger, sd.InvalidateOnError(time.Second))
	return
}

func (s *Cluster) factory(instance string) (endpoint.Endpoint, io.Closer, error) {
	node := &NodeLocal{}
	if err := node.Unmarshal(instance); err != nil {
		s.logger.Error("node instance failed", zap.Error(err), zap.String("node", instance))
		return nil, nil, err
	}
	// connect
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		protc := node.Protocol()
		if protc == ProtocolHTTP {
			// client := http.Client{}
			// client.Do()
		}

		return nil, fmt.Errorf("texx-----%s", node.Id)
	}, nil, nil
}

func (s *Cluster) Shutdown() {
	s.once.Do(func() {
		if s.cancelFn != nil {
			s.cancelFn()
		}
	})
}

func New(ctx context.Context, logger *zap.Logger, node Node, c Configuration) (*Cluster, error) {
	client, err := etcdv3.NewClient(context.Background(), c.Etcd.Endpoints, etcdv3.ClientOptions{
		DialTimeout:   time.Duration(c.Etcd.DialTimeout) * time.Second,
		DialKeepAlive: time.Duration(c.Etcd.DialKeepAliveTime) * time.Second,
		Username:      c.Etcd.Username,
		Password:      c.Etcd.Password,
		Cert:          c.Etcd.Cert,
		Key:           c.Etcd.Key,
		CACert:        c.Etcd.CACert,
	})

	if err != nil {
		logger.Error("Cluster connect to etcd address failed", zap.Error(err))
		return nil, err
	}

	s := &Cluster{
		config: c,
		client: client,
		logger: logger,
		node:   node,
	}

	s.nodes.Store(make(map[string]Node))
	s.subnodes.Store(make(map[string]Node))
	s.services.Store(make(map[string]*sd.SoildStateEndpointer))

	if err := s.listen(); err != nil {
		return nil, err
	}

	go s.serve(ctx)
	return s, nil
}

func JoinServiceName(names ...string) string {
	return strings.Join(names, "/")
}

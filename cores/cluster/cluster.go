package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/doublemo/linna/cores/endpoint"
	"github.com/doublemo/linna/cores/sd"
	"github.com/doublemo/linna/cores/sd/etcdv3"
	"go.uber.org/zap"
)

type EtcdConfiguration struct {
	Endpoints         []string `json:"endpoints" yaml:"endpoints" usage:"Etcd address a list of URLs."`
	DialTimeout       int      `json:"dial_timeout" yaml:"dial_timeout" usage:"The timeout for failing to establish a connection."`
	DialKeepAliveTime int      `json:"dial_keep_alive_time" yaml:"dial_keep_alive_time" usage:"The time after which client pings the server to see if transport is alive."`
	Username          string   `json:"username" yaml:"username" usage:"A user name for authentication"`
	Password          string   `json:"password" yaml:"password" usage:"A password for authentication"`
	Cert              string   `json:"cert" yaml:"cert" usage:"The client secure credentials"`
	Key               string   `json:"key" yaml:"key" usage:"The client secure credentials"`
	CACert            string   `json:"ca_cert" yaml:"ca_cert" usage:"The client secure credentials"`
}

type Configuration struct {
	Name       string            `json:"name" yaml:"name" usage:"Cluster name"`
	Prefix     string            `json:"prefex" yaml:"prefix" usage:"prefix"`
	SubService bool              `json:"sub_service" yaml:"sub_service" usage:"is a sub service"`
	Etcd       EtcdConfiguration `json:"etcd" yaml:"etcd" usage:"Etcd settings"`
}

func (c Configuration) Check() error {
	return nil
}

func NewConfiguration() Configuration {
	return Configuration{
		Name:   "linna",
		Prefix: "/cluster/v1",
		Etcd: EtcdConfiguration{
			Endpoints:         []string{"http://127.0.0.1:2379"},
			DialTimeout:       3,
			DialKeepAliveTime: 15,
		},
	}
}

type Cluster struct {
	config       Configuration
	client       etcdv3.Client
	logger       *zap.Logger
	node         Node
	instancer    sd.Instancer
	subinstancer sd.Instancer
	endpoint     sd.Endpointer
	registrar    sd.Registrar
	cancelFn     context.CancelFunc
	once         sync.Once
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
			fmt.Println(evt.Instances)

		case evt := <-eventSub:
			if evt.Err != nil {
				s.logger.Warn("sub event error", zap.Error(evt.Err))
				continue
			}
			fmt.Println("sub event:", evt.Instances)

		case <-ticker.C:

		case <-ctx.Done():
			return
		}
	}
}

func (s *Cluster) listen(key string) (err error) {
	s.instancer, err = etcdv3.NewInstancer(s.client, key, s.logger)
	if err != nil {
		s.logger.Error("Cluster instancer failed", zap.Error(err))
		return
	}

	nodeInfo, err := s.node.Marshal()
	if err != nil {
		s.logger.Error("Node marshal failed", zap.Error(err))
		return err
	}

	service := etcdv3.Service{
		Key:   key + "/" + s.node.ID(),
		Value: nodeInfo,
		TTL:   etcdv3.NewTTLOption(time.Second*3, time.Second*10),
	}

	s.registrar = etcdv3.NewRegistrar(s.client, service, s.logger)
	s.registrar.Register()
	s.endpoint = sd.NewEndpointer(s.instancer, s.factory, s.logger, sd.InvalidateOnError(time.Second))
	return
}

func (s *Cluster) listenSub(key string) error {
	instancer, err := etcdv3.NewInstancer(s.client, key, s.logger)
	if err != nil {
		s.logger.Error("Cluster instancer failed", zap.Error(err))
		return err
	}

	s.subinstancer = instancer
	return nil
}

func (s *Cluster) factory(instance string) (endpoint.Endpoint, io.Closer, error) {
	node := &NodeLocal{}
	if err := node.Unmarshal(instance); err != nil {
		s.logger.Error("node instance failed", zap.Error(err), zap.String("node", instance))
		return nil, nil, err
	}

	// connect
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return nil, errors.New("LALALALAL")
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

	if err := s.listen(JoinServiceName(c.Prefix, c.Name)); err != nil {
		return nil, err
	}

	if err := s.listenSub(JoinServiceName(c.Prefix, "sub"+"_"+c.Name)); err != nil {
		return nil, err
	}

	go s.serve(ctx)
	return s, nil
}

func JoinServiceName(names ...string) string {
	return strings.Join(names, "/")
}

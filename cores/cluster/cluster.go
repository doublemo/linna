package cluster

import (
	"context"
	"strings"

	"github.com/doublemo/linna/cores/endpoint"
	"github.com/doublemo/linna/cores/sd"
	"github.com/doublemo/linna/cores/sd/etcdv3"
	"go.uber.org/zap"
)

const (
	SERVICE_PREFIX_LINNA = "linna/services"
	SERVICE_PREFIX_SUB   = "linna/subservices"
)

type Cluster struct {
	logger      *zap.Logger
	client      etcdv3.Client
	services    sd.Instancer
	subServices sd.Instancer
	cancelFn    context.CancelFunc
}

func (c *Cluster) Endpoints(id string) ([]endpoint.Endpoint, error) {
	return nil, nil
}

func (c *Cluster) Register() error {
	return nil
}

func (c *Cluster) serve(ctx context.Context) {
	serviceChan := make(chan sd.Event, 1)
	subChan := make(chan sd.Event, 1)
	c.services.Register(serviceChan)
	c.subServices.Register(subChan)

	defer func() {
		c.services.Deregister(serviceChan)
		c.subServices.Deregister(subChan)
		close(serviceChan)
		close(subChan)
	}()

	ctx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	for {
		select {
		case evt := <-serviceChan:
			if evt.Err != nil {
				c.logger.Error("cluster shutdowned, The channel read failed from linna services", zap.Error(evt.Err))
				return
			}

		case subevt := <-subChan:
			if subevt.Err != nil {
				c.logger.Error("cluster shutdowned, The channel read failed from sub services", zap.Error(subevt.Err))
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func New(ctx context.Context, logger *zap.Logger, prefix string, client etcdv3.Client) (*Cluster, error) {
	instancer, err := etcdv3.NewInstancer(client, JoinServiceName(prefix, SERVICE_PREFIX_LINNA), logger)
	if err != nil {
		return nil, err
	}

	subInstancer, err := etcdv3.NewInstancer(client, JoinServiceName(prefix, SERVICE_PREFIX_SUB), logger)
	if err != nil {
		return nil, err
	}

	c := &Cluster{
		logger:      logger,
		client:      client,
		services:    instancer,
		subServices: subInstancer,
	}

	go c.serve(ctx)
	return c, nil
}

func JoinServiceName(names ...string) string {
	return strings.Join(names, "/")
}

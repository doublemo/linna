package sd

import (
	"github.com/doublemo/linna/cores/endpoint"
	"go.uber.org/zap"
)

type SoildStateEndpointer struct {
	cache *endpointCache
}

func (de *SoildStateEndpointer) Update(event Event) {
	de.cache.Update(event)
}

// Endpoints implements Endpointer.
func (de *SoildStateEndpointer) Endpoints() ([]endpoint.Endpoint, error) {
	return de.cache.Endpoints()
}

func NewSoildStateEndpointer(f Factory, logger *zap.Logger, options ...EndpointerOption) *SoildStateEndpointer {
	opts := endpointerOptions{}
	for _, opt := range options {
		opt(&opts)
	}
	se := &SoildStateEndpointer{
		cache: newEndpointCache(f, logger, opts),
	}
	return se
}

package linna

import (
	"context"
	"fmt"

	"github.com/doublemo/nana/api"
)

func (s *ApiServer) SessionRefresh(ctx context.Context, in *api.SessionRefreshRequest) (*api.Session, error) {
	fmt.Println(in)
	return &api.Session{
		Created: true,
	}, nil
}

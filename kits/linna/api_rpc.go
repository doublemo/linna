package linna

import (
	"context"
	"fmt"

	"github.com/doublemo/nana/api"
)

func (s *ApiServer) RpcFunc(ctx context.Context, in *api.Rpc) (*api.Rpc, error) {
	fmt.Println("rpc call:", in)
	fn, ok := s.runtime.Rpc(in.Id)
	if !ok {
		fmt.Println("不存在")
	} else {
		fmt.Println(fn(ctx, &RuntimeRpcValues{Id: in.Id}, "okkkkkkkkk"))
	}
	return &api.Rpc{
		Id: "dddd",
	}, nil
}

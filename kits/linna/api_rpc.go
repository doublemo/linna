package linna

import (
	"context"
	"strings"

	"github.com/doublemo/nana/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (s *ApiServer) RpcFunc(ctx context.Context, in *api.Rpc) (*api.Rpc, error) {
	if in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "RPC ID must be set")
	}

	id := strings.ToLower(in.Id)
	fn, ok := s.runtime.Rpc(id)
	if !ok || fn == nil {
		return nil, status.Error(codes.NotFound, "RPC function not found")
	}

	headers := make(map[string][]string, 0)
	queryParams := make(map[string][]string, 0)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "RPC function could not get incoming context")
	}

	for k, vs := range md {
		// Only process the keys representing custom query parameters.
		if strings.HasPrefix(k, "q_") {
			queryParams[k[2:]] = vs
		} else {
			headers[k] = vs
		}
	}

	values := &RuntimeRpcValues{
		Id:          id,
		Headers:     headers,
		QueryParams: queryParams,
	}

	code, result, err := fn(ctx, values, in.Payload)
	if err != nil {
		return nil, status.Error(code, err.Error())
	}

	return &api.Rpc{
		Id:      in.Id,
		Payload: result,
	}, nil
}

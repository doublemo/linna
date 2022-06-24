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

package linna

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	"github.com/doublemo/linna/pb"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	grpcgw "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

type ctxFullMethodKey struct{}

type ApiConfiguration struct {
	ServerKey            string            `yaml:"server_key" json:"server_key" usage:"Server key to use to establish a connection to the server."`
	Port                 int               `yaml:"port" json:"port" usage:"The port for accepting connections from the client for the given interface(s), address(es), and protocol(s). Default 7350."`
	Address              string            `yaml:"address" json:"address" usage:"The IP address of the interface to listen for client traffic on. Default listen on all available addresses/interfaces."`
	Protocol             string            `yaml:"protocol" json:"protocol" usage:"The network protocol to listen for traffic on. Possible values are 'tcp' for both IPv4 and IPv6, 'tcp4' for IPv4 only, or 'tcp6' for IPv6 only. Default 'tcp'."`
	MaxMessageSizeBytes  int64             `yaml:"max_message_size_bytes" json:"max_message_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from the client socket per message. Used for real-time connections."`
	MaxRequestSizeBytes  int64             `yaml:"max_request_size_bytes" json:"max_request_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from clients per request. Used for gRPC and HTTP connections."`
	ReadBufferSizeBytes  int               `yaml:"read_buffer_size_bytes" json:"read_buffer_size_bytes" usage:"Size in bytes of the pre-allocated socket read buffer. Default 4096."`
	WriteBufferSizeBytes int               `yaml:"write_buffer_size_bytes" json:"write_buffer_size_bytes" usage:"Size in bytes of the pre-allocated socket write buffer. Default 4096."`
	ReadTimeoutMs        int               `yaml:"read_timeout_ms" json:"read_timeout_ms" usage:"Maximum duration in milliseconds for reading the entire request. Used for HTTP connections."`
	WriteTimeoutMs       int               `yaml:"write_timeout_ms" json:"write_timeout_ms" usage:"Maximum duration in milliseconds before timing out writes of the response. Used for HTTP connections."`
	IdleTimeoutMs        int               `yaml:"idle_timeout_ms" json:"idle_timeout_ms" usage:"Maximum amount of time in milliseconds to wait for the next request when keep-alives are enabled. Used for HTTP connections."`
	WriteWaitMs          int               `yaml:"write_wait_ms" json:"write_wait_ms" usage:"Time in milliseconds to wait for an ack from the client when writing data. Used for real-time connections."`
	PongWaitMs           int               `yaml:"pong_wait_ms" json:"pong_wait_ms" usage:"Time in milliseconds to wait between pong messages received from the client. Used for real-time connections."`
	PingPeriodMs         int               `yaml:"ping_period_ms" json:"ping_period_ms" usage:"Time in milliseconds to wait between sending ping messages to the client. This value must be less than the pong_wait_ms. Used for real-time connections."`
	PingBackoffThreshold int               `yaml:"ping_backoff_threshold" json:"ping_backoff_threshold" usage:"Minimum number of messages received from the client during a single ping period that will delay the sending of a ping until the next ping period, to avoid sending unnecessary pings on regularly active connections. Default 20."`
	OutgoingQueueSize    int               `yaml:"outgoing_queue_size" json:"outgoing_queue_size" usage:"The maximum number of messages waiting to be sent to the client. If this is exceeded the client is considered too slow and will disconnect. Used when processing real-time connections."`
	SSLCertificate       string            `yaml:"ssl_certificate" json:"ssl_certificate" usage:"Path to certificate file if you want the server to use SSL directly. Must also supply ssl_private_key. NOT recommended for production use."`
	SSLPrivateKey        string            `yaml:"ssl_private_key" json:"ssl_private_key" usage:"Path to private key file if you want the server to use SSL directly. Must also supply ssl_certificate. NOT recommended for production use."`
	CertPEMBlock         []byte            `yaml:"-" json:"-"` // Created by fully reading the file contents of SSLCertificate, not set from input args directly.
	KeyPEMBlock          []byte            `yaml:"-" json:"-"` // Created by fully reading the file contents of SSLPrivateKey, not set from input args directly.
	TLSCert              []tls.Certificate `yaml:"-" json:"-"` // Created by processing CertPEMBlock and KeyPEMBlock, not set from input args directly.
}

type ApiServer struct {
	pb.UnimplementedLinnaServer
	config            Configuration
	metrics           metrics.Metrics
	grpcServer        *grpc.Server
	grpcGatewayServer *http.Server
}

func (s *ApiServer) Serve() *ApiServer {
	s.serveGrpc()
	s.serveGrpcgateway()
	return s
}

func (s *ApiServer) serveGrpc() {
	log := logger.StartupLogger()
	serverOpts := []grpc.ServerOption{
		grpc.StatsHandler(&metrics.MetricsGrpcHandler{MetricsFn: s.metrics.Api}),
		grpc.MaxRecvMsgSize(int(s.config.Api.MaxRequestSizeBytes)),
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			ctx, err := securityInterceptorFunc(ctx, s.config, req, info)
			if err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
	}

	if s.config.Api.TLSCert != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewServerTLSFromCert(&s.config.Api.TLSCert[0])))
	}

	s.grpcServer = grpc.NewServer(serverOpts...)
	pb.RegisterLinnaServer(s.grpcServer, s)
	log.Info("Starting API server for gRPC requests", zap.Int("port", s.config.Api.Port-1))
	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf("%v:%d", s.config.Api.Address, s.config.Api.Port-1))
		if err != nil {
			log.Fatal("API server listener failed to start", zap.Error(err))
		}

		if err := s.grpcServer.Serve(listener); err != nil {
			log.Fatal("API server listener failed", zap.Error(err))
		}
	}()
}

func (s *ApiServer) serveGrpcgateway() {
	log := logger.StartupLogger()
	var gatewayContextTimeoutMs string
	if s.config.Api.IdleTimeoutMs > 500 {
		// Ensure the GRPC Gateway timeout is just under the idle timeout (if possible) to ensure it has priority.
		grpcgw.DefaultContextTimeout = time.Duration(s.config.Api.IdleTimeoutMs-500) * time.Millisecond
		gatewayContextTimeoutMs = fmt.Sprintf("%vm", s.config.Api.IdleTimeoutMs-500)
	} else {
		grpcgw.DefaultContextTimeout = time.Duration(s.config.Api.IdleTimeoutMs) * time.Millisecond
		gatewayContextTimeoutMs = fmt.Sprintf("%vm", s.config.Api.IdleTimeoutMs)
	}

	ctx := context.Background()
	grpcGateway := grpcgw.NewServeMux(
		grpcgw.WithMetadata(func(ctx context.Context, r *http.Request) metadata.MD {
			if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, "/v2/rpc/") {
				return metadata.MD{}
			}

			q := r.URL.Query()
			p := make(map[string][]string, len(q))
			for k, vs := range q {
				if k == "http_key" {
					continue
				}
				p["q_"+k] = vs
			}
			return metadata.MD(p)
		}),
		grpcgw.WithMarshalerOption(grpcgw.MIMEWildcard, &grpcgw.HTTPBodyMarshaler{
			Marshaler: &grpcgw.JSONPb{
				MarshalOptions: protojson.MarshalOptions{
					UseProtoNames:  true,
					UseEnumNumbers: true,
				},
				UnmarshalOptions: protojson.UnmarshalOptions{
					DiscardUnknown: true,
				},
			},
		}),
	)

	dialAddr := fmt.Sprintf("127.0.0.1:%d", s.config.Api.Port-1)
	if s.config.Api.Address != "" {
		dialAddr = fmt.Sprintf("%v:%d", s.config.Api.Address, s.config.Api.Port-1)
	}
	dialOpts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(int(s.config.Api.MaxRequestSizeBytes)),
			grpc.MaxCallRecvMsgSize(math.MaxInt32),
		),
	}

	if s.config.Api.TLSCert != nil {
		// GRPC-Gateway only ever dials 127.0.0.1 so we can be lenient on server certificate validation.
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(s.config.Api.CertPEMBlock) {
			log.Fatal("Failed to load PEM certificate from socket SSL certificate file")
		}
		cert := credentials.NewTLS(&tls.Config{RootCAs: certPool, InsecureSkipVerify: true})
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(cert))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}

	if err := pb.RegisterLinnaHandlerFromEndpoint(ctx, grpcGateway, dialAddr, dialOpts); err != nil {
		log.Fatal("API server gateway registration failed", zap.Error(err))
	}

	grpcGatewayRouter := mux.NewRouter()
	// Special case routes. Do NOT enable compression on WebSocket route, it results in "http: response.Write on hijacked connection" errors.
	grpcGatewayRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }).Methods("GET")
	grpcGatewayRouter.HandleFunc("/ws", NewWebsocketAcceptor(s.config, s.metrics)).Methods("GET")

	grpcGatewayMux := mux.NewRouter()
	//grpcGatewayMux.HandleFunc("/v2/rpc/{id:.*}", s.RpcFuncHttp).Methods("GET", "POST")
	grpcGatewayMux.NewRoute().Handler(grpcGateway)

	handlerWithDecompressRequest := decompressHandler(log, grpcGatewayMux)
	handlerWithCompressResponse := handlers.CompressHandler(handlerWithDecompressRequest)
	maxMessageSizeBytes := s.config.Api.MaxRequestSizeBytes
	handlerWithMaxBody := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check max body size before decompressing incoming request body.
		r.Body = http.MaxBytesReader(w, r.Body, maxMessageSizeBytes)
		handlerWithCompressResponse.ServeHTTP(w, r)
	})
	grpcGatewayRouter.NewRoute().HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure some request headers have required values.
		// Override any value set by the client if needed.
		r.Header.Set("Grpc-Timeout", gatewayContextTimeoutMs)

		// Add constant response headers.
		w.Header().Add("Cache-Control", "no-store, no-cache, must-revalidate")

		// Allow GRPC Gateway to handle the request.
		handlerWithMaxBody.ServeHTTP(w, r)
	})

	// Enable CORS on all requests.
	CORSHeaders := handlers.AllowedHeaders([]string{"Authorization", "Content-Type", "User-Agent"})
	CORSOrigins := handlers.AllowedOrigins([]string{"*"})
	CORSMethods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE"})
	handlerWithCORS := handlers.CORS(CORSHeaders, CORSOrigins, CORSMethods)(grpcGatewayRouter)

	// Set up and start GRPC Gateway server.
	s.grpcGatewayServer = &http.Server{
		ReadTimeout:    time.Millisecond * time.Duration(int64(s.config.Api.ReadTimeoutMs)),
		WriteTimeout:   time.Millisecond * time.Duration(int64(s.config.Api.WriteTimeoutMs)),
		IdleTimeout:    time.Millisecond * time.Duration(int64(s.config.Api.IdleTimeoutMs)),
		MaxHeaderBytes: 5120,
		Handler:        handlerWithCORS,
	}
	if s.config.Api.TLSCert != nil {
		s.grpcGatewayServer.TLSConfig = &tls.Config{Certificates: s.config.Api.TLSCert}
	}

	log.Info("Starting API server gateway for HTTP requests", zap.Int("port", s.config.Api.Port))
	go func() {
		listener, err := net.Listen(s.config.Api.Protocol, fmt.Sprintf("%v:%d", s.config.Api.Address, s.config.Api.Port))
		if err != nil {
			log.Fatal("API server gateway listener failed to start", zap.Error(err))
		}

		if s.config.Api.TLSCert != nil {
			if err := s.grpcGatewayServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
				log.Fatal("API server gateway listener failed", zap.Error(err))
			}
		} else {
			if err := s.grpcGatewayServer.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Fatal("API server gateway listener failed", zap.Error(err))
			}
		}
	}()

}

func (s *ApiServer) Stop() {
	log := logger.StartupLogger()
	// 1. Stop GRPC Gateway server first as it sits above GRPC server. This also closes the underlying listener.
	if err := s.grpcGatewayServer.Shutdown(context.Background()); err != nil {
		log.Error("API server gateway listener shutdown failed", zap.Error(err))
	}
	// 2. Stop GRPC server. This also closes the underlying listener.
	s.grpcServer.GracefulStop()
}

func NewApiServer(c Configuration, m metrics.Metrics) *ApiServer {
	return &ApiServer{
		config:  c,
		metrics: m,
	}
}

func NewApiConfiguration() ApiConfiguration {
	return ApiConfiguration{
		ServerKey:            "linna-server-key",
		Port:                 19080,
		Address:              "",
		Protocol:             "tcp",
		MaxMessageSizeBytes:  4096,
		MaxRequestSizeBytes:  262_144, // 256 KB.
		ReadBufferSizeBytes:  4096,
		WriteBufferSizeBytes: 4096,
		ReadTimeoutMs:        10 * 1000,
		WriteTimeoutMs:       10 * 1000,
		IdleTimeoutMs:        60 * 1000,
		WriteWaitMs:          5000,
		PongWaitMs:           25000,
		PingPeriodMs:         15000,
		PingBackoffThreshold: 20,
		OutgoingQueueSize:    64,
		SSLCertificate:       "",
		SSLPrivateKey:        "",
	}
}

func securityInterceptorFunc(ctx context.Context, c Configuration, req interface{}, info *grpc.UnaryServerInfo) (context.Context, error) {
	return context.WithValue(ctx, ctxFullMethodKey{}, info.FullMethod), nil
}

func decompressHandler(log *zap.Logger, h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Content-Encoding") {
		case "gzip":
			gr, err := gzip.NewReader(r.Body)
			if err != nil {
				log.Debug("Error processing gzip request body, attempting to read uncompressed", zap.Error(err))
				break
			}
			r.Body = gr
		case "deflate":
			r.Body = flate.NewReader(r.Body)
		default:
			// No request compression.
		}
		h.ServeHTTP(w, r)
	})
}

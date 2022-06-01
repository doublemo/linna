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
	"strconv"
	"strings"
	"time"

	"github.com/doublemo/linna/internal/logger"
	"github.com/doublemo/linna/internal/metrics"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	grpcgw "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ApiConfiguration api配置
type ApiConfiguration struct {
	ServerKey            string            `yaml:"server_key" json:"server_key" usage:"Server key to use to establish a connection to the server."`
	Address              string            `yaml:"address"`
	Port                 int               `yaml:"port"`
	Protocol             string            `yaml:"protocol" json:"protocol" usage:"The network protocol to listen for traffic on. Possible values are 'tcp' for both IPv4 and IPv6, 'tcp4' for IPv4 only, or 'tcp6' for IPv6 only. Default 'tcp'."`
	MaxMessageSizeBytes  int               `yaml:"max_message_size_bytes" json:"max_message_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from the client socket per message. Used for real-time connections."`
	MaxRequestSizeBytes  int               `yaml:"max_request_size_bytes" json:"max_request_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from clients per request. Used for gRPC and HTTP connections."`
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
	metrics           metrics.Metrics
	runtime           *Runtime
	grpcServer        *grpc.Server
	grpcGatewayServer *http.Server
}

func NewApiServer(metric metrics.Metrics, c Configuration) *ApiServer {
	var gatewayContextTimeoutMs string
	if c.Api.IdleTimeoutMs > 500 {
		// Ensure the GRPC Gateway timeout is just under the idle timeout (if possible) to ensure it has priority.
		grpcgw.DefaultContextTimeout = time.Duration(c.Api.IdleTimeoutMs-500) * time.Millisecond
		gatewayContextTimeoutMs = fmt.Sprintf("%vm", c.Api.IdleTimeoutMs-500)
	} else {
		grpcgw.DefaultContextTimeout = time.Duration(c.Api.IdleTimeoutMs) * time.Millisecond
		gatewayContextTimeoutMs = fmt.Sprintf("%vm", c.Api.IdleTimeoutMs)
	}

	logger, startupLogger := logger.Logger()
	serverOpt := []grpc.ServerOption{
		grpc.StatsHandler(&metrics.MetricsGrpcHandler{MetricsFn: metric.Api}),
		grpc.MaxRecvMsgSize(c.Api.MaxRequestSizeBytes),
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
			return handler(ctx, req)
		}),
	}

	grpcServer := grpc.NewServer(serverOpt...)
	s := &ApiServer{
		metrics:    metric,
		grpcServer: grpcServer,
	}

	addr := net.JoinHostPort(c.Api.Address, strconv.Itoa(c.Api.Port-1))
	go func() {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			startupLogger.Fatal("API server listener failed to start", zap.Error(err))
		}

		if err := grpcServer.Serve(listener); err != nil {
			startupLogger.Fatal("API server listener failed", zap.Error(err))
		}
	}()

	grpcGateway := grpcgw.NewServeMux(
		grpcgw.WithMetadata(func(ctx context.Context, r *http.Request) metadata.MD {
			if r.Method == "GET" || !strings.HasPrefix(r.URL.Path, "/v1/rpc/") {
				return metadata.MD{}
			}

			q := r.URL.Query()
			p := make(map[string][]string, len(q))
			for k, vs := range q {
				if k == "sign" {
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

	dialAddr := addr
	if c.Api.Address == "" {
		dialAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Api.Port-1))
	}

	fmt.Println(dialAddr)
	dialOpts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(c.Api.MaxRequestSizeBytes),
			grpc.MaxCallRecvMsgSize(math.MaxInt32),
		),
	}
	if c.Api.TLSCert != nil {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(c.Api.CertPEMBlock) {
			startupLogger.Fatal("Failed to load PEM certificate from socket SSL certificate file")
		}
		cert := credentials.NewTLS(&tls.Config{RootCAs: certPool, InsecureSkipVerify: true})
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(cert))
	} else {
		dialOpts = append(dialOpts, grpc.WithInsecure())
	}

	grpcGatewayRouter := mux.NewRouter()
	grpcGatewayRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }).Methods("GET")

	grpcGatewayMux := mux.NewRouter()
	//grpcGatewayMux.HandleFunc("/v2/rpc/{id:.*}", s.RpcFuncHttp).Methods("GET", "POST")
	grpcGatewayMux.NewRoute().Handler(grpcGateway)
	handlerWithDecompressRequest := decompressHandler(logger, grpcGatewayMux)
	handlerWithCompressResponse := handlers.CompressHandler(handlerWithDecompressRequest)
	maxMessageSizeBytes := c.Api.MaxRequestSizeBytes
	handlerWithMaxBody := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check max body size before decompressing incoming request body.
		r.Body = http.MaxBytesReader(w, r.Body, int64(maxMessageSizeBytes))
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
		ReadTimeout:    time.Millisecond * time.Duration(int64(c.Api.ReadTimeoutMs)),
		WriteTimeout:   time.Millisecond * time.Duration(int64(c.Api.WriteTimeoutMs)),
		IdleTimeout:    time.Millisecond * time.Duration(int64(c.Api.IdleTimeoutMs)),
		MaxHeaderBytes: 5120,
		Handler:        handlerWithCORS,
	}
	if c.Api.TLSCert != nil {
		s.grpcGatewayServer.TLSConfig = &tls.Config{Certificates: c.Api.TLSCert}
	}

	startupLogger.Info("Starting API server gateway for HTTP requests", zap.Int("port", c.Api.Port))
	go func() {
		listener, err := net.Listen(c.Api.Protocol, fmt.Sprintf("%v:%d", c.Api.Address, c.Api.Port))
		if err != nil {
			startupLogger.Fatal("API server gateway listener failed to start", zap.Error(err))
		}

		if c.Api.TLSCert != nil {
			if err := s.grpcGatewayServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
				startupLogger.Fatal("API server gateway listener failed", zap.Error(err))
			}
		} else {
			if err := s.grpcGatewayServer.Serve(listener); err != nil && err != http.ErrServerClosed {
				startupLogger.Fatal("API server gateway listener failed", zap.Error(err))
			}
		}
	}()

	return s
}

func (s *ApiServer) Stop() {
	log := logger.ConsoleLogger()
	// 1. Stop GRPC Gateway server first as it sits above GRPC server. This also closes the underlying listener.
	if err := s.grpcGatewayServer.Shutdown(context.Background()); err != nil {
		log.Error("API server gateway listener shutdown failed", zap.Error(err))
	}
	// 2. Stop GRPC server. This also closes the underlying listener.
	s.grpcServer.GracefulStop()
}

func (s *ApiServer) Healthcheck(ctx context.Context, in *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func decompressHandler(logger *zap.Logger, h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Content-Encoding") {
		case "gzip":
			gr, err := gzip.NewReader(r.Body)
			if err != nil {
				logger.Debug("Error processing gzip request body, attempting to read uncompressed", zap.Error(err))
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

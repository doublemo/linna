package cluster

import (
	"errors"
	"net"
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
	Name           string            `json:"name" yaml:"name" usage:"Cluster name"`
	IP             string            `json:"ip" yaml:"ip" usage:"Cluster ip"`
	Prefix         string            `json:"prefex" yaml:"prefix" usage:"prefix"`
	Port           int               `yaml:"port" json:"port" usage:"The port for accepting connections from the client for the given interface(s), address(es), and protocol(s). Default 7350."`
	Address        string            `yaml:"address" json:"address" usage:"The IP address of the interface to listen for client traffic on. Default listen on all available addresses/interfaces."`
	Protocol       string            `yaml:"protocol" json:"protocol" usage:"The network protocol to listen for traffic on. Possible values are 'tcp' for both IPv4 and IPv6, 'tcp4' for IPv4 only, or 'tcp6' for IPv6 only. Default 'tcp'."`
	ServiceName    string            `yaml:"service_name" json:"service_name" usage:"Service name."`
	ServiceDomain  string            `yaml:"service_domain" json:"service_domain" usage:"Service domain."`
	SSLCertificate string            `yaml:"ssl_certificate" json:"ssl_certificate" usage:"Path to certificate file if you want the server to use SSL directly. Must also supply ssl_private_key. NOT recommended for production use."`
	SSLPrivateKey  string            `yaml:"ssl_private_key" json:"ssl_private_key" usage:"Path to private key file if you want the server to use SSL directly. Must also supply ssl_certificate. NOT recommended for production use."`
	Etcd           EtcdConfiguration `json:"etcd" yaml:"etcd" usage:"Etcd settings"`
}

func (c Configuration) Check() error {
	return nil
}

func NewConfiguration() Configuration {
	ip, _ := LocalIP()
	return Configuration{
		Name:          "linna",
		IP:            ip.String(),
		Prefix:        "/cluster/v1",
		Port:          39080,
		Address:       "",
		Protocol:      "",
		ServiceName:   "linna",
		ServiceDomain: "127.0.0.1:18080",
		Etcd: EtcdConfiguration{
			Endpoints:         []string{"http://127.0.0.1:2379"},
			DialTimeout:       3,
			DialKeepAliveTime: 15,
		},
	}
}

func LocalIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				ip := ipNet.IP.To4()
				if ip[0] == 10 || ip[0] == 172 && (ip[1] >= 16 && ip[1] < 32) || ip[0] == 192 && ip[1] == 168 {
					return ip, nil
				}
			}
		}
	}

	return nil, errors.New("Failed to get ip address")
}

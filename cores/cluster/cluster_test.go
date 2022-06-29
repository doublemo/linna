package cluster_test

import (
	"context"
	"testing"
	"time"

	"github.com/doublemo/linna/cores/sd/etcdv3"
)

func TestCluster(t *testing.T) {
	client, err := etcdv3.NewClient(context.Background(), []string{"http://192.168.0.228:2379", "http://192.168.0.228:2380", "http://192.168.0.228:2381"}, etcdv3.ClientOptions{
		DialTimeout:   time.Second,
		DialKeepAlive: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// c, err := cluster.New(context.Background(), zap.NewNop(), "/linna/v1", client)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// time.Sleep(time.Second)
	// node := cluster.NewNode("tewst1", "grpc", "192.168.0.228:88989")
	// node.SetValue("sss", "xxxxx")
	// if err := c.Join(node); err != nil {
	// 	t.Fatal(err)
	// }
	time.Sleep(time.Second * 5)
	t.Fatal(client.GetEntries("/linna/v1"))
}

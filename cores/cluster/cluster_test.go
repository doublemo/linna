package cluster_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/doublemo/linna/cores/cluster"
	"github.com/doublemo/linna/cores/sd/etcdv3"
	"go.uber.org/zap"
)

func TestCluster(t *testing.T) {
	client, err := etcdv3.NewClient(context.Background(), []string{"http://192.168.0.228:2379", "http://192.168.0.228:2380", "http://192.168.0.228:2381"}, etcdv3.ClientOptions{
		DialTimeout:   time.Second,
		DialKeepAlive: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan struct{}, 1)
	go client.WatchPrefix("/test", ch)
	go func() {
		for range ch {
			fmt.Println(client.GetEntries("/test"))
		}
	}()

	err = client.Register(etcdv3.Service{Key: "/test/v1", Value: "testValue"})
	if err != nil {
		t.Fatal(err)
	}

	c, err := cluster.New(context.Background(), zap.NewNop(), "/linna/v1", client)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(c)
	data, _ := json.Marshal(cluster.NewNodeLocal("ddddd"))
	fmt.Println(string(data))
	time.Sleep(time.Second * 13)
	t.Fatal(client.GetEntries("/test"))
}

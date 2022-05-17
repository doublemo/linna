package linna

import (
	"context"
	"testing"
)

func TestRuntime(t *testing.T) {
	data, _, err := NewRuntime(context.Background(), Configuration{
		Datadir: "E:/datatest",
		Runtime: RuntimeConfiguration{
			Path: "E:/datatest",
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Log(data)
}

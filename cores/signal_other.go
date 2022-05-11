//go:build !windows
// +build !windows

package cores

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Signal 处理系统信号
func Signal(ctx context.Context, handle func(SignalCommand)) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP)
loop:
	for {
		select {
		case sig := <-c:
			switch sig {
			case syscall.SIGINT:
				handle(SignalINT)

			case syscall.SIGTERM:
				handle(SignalTERM)

			case syscall.SIGUSR1:
				handle(SignalUSR1)

			case syscall.SIGUSR2:
				handle(SignalUSR2)

			case syscall.SIGHUP:
				handle(SignalHUP)
			}

			// go
			goto loop

		case <-ctx.Done():
			return
		}
	}
}

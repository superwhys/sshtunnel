package main

import (
	"context"

	"github.com/superwhys/sshtunnel"
)

func main() {
	tunnel := sshtunnel.NewTunnel(&sshtunnel.SshConfig{
		User:         "hoven",
		HostName:     "10.15.25.23:22",
		IdentityFile: "/Users/yong/.ssh/id_rsa",
	})

	if err := tunnel.Forward(context.TODO(), "localhost:26379", "10.15.25.23:6379"); err != nil {
		panic(err)
	}

	tunnel.Wait()
}

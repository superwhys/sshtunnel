package main

import (
	"context"

	"github.com/superwhys/sshtunnel"
)

func main() {
	tunnel := sshtunnel.NewTunnel(&sshtunnel.SshConfig{
		User:         "fdz",
		HostName:     "s9ga.cnns.net:65522",
		IdentityFile: "/Users/yong/.ssh/id_rsa_cnns",
	})

	if err := tunnel.Forward(context.TODO(), "localhost:29950", "10.0.0.59:29917"); err != nil {
		panic(err)
	}

	tunnel.Wait()
}

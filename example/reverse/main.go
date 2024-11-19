// File:		main.go
// Created by:	Hoven
// Created on:	2024-11-19
//
// This file is part of the Example Project.
//
// (c) 2024 Example Corp. All rights reserved.

package main

import (
	"context"

	"github.com/superwhys/sshtunnel"
)

func main() {
	tunnel := sshtunnel.NewTunnel(&sshtunnel.SshConfig{
		User:         "hoven",
		HostName:     "10.11.43.115:22",
		IdentityFile: "/Users/yong/.ssh/id_rsa_cnns",
	})

	if err := tunnel.Reverse(context.TODO(), "localhost:2222", "10.15.25.23:22"); err != nil {
		panic(err)
	}

	tunnel.Wait()
}

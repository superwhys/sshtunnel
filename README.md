# SSH Tunnel
一个用Go语言实现的SSH隧道工具，支持端口转发和反向代理功能。

## 特性

- 支持SSH端口转发（Forward）
- 支持SSH反向代理（Reverse）
- 自动重连机制
- 支持多跳SSH隧道
- 保活连接（Keep-Alive）机制

## 安装 
```bash
go get github.com/sueprwhys/sshtunnel
```

## 使用示例

### Forward
```go
package main

import (
	"context"

	"github.com/superwhys/sshtunnel"
)

func main() {
	tunnel := sshtunnel.NewTunnel(&sshtunnel.SshConfig{
		User:         "superwhys",
		HostName:     "remote-server.com:22",
		IdentityFile: "~/.ssh/id_rsa",
	})

	if err := tunnel.Forward(context.TODO(), "localhost:29920", "10.0.0.60:80"); err != nil {
		panic(err)
	}

	tunnel.Wait()
}
```

### Reverse

```go
package main

import (
	"context"

	"github.com/superwhys/sshtunnel"
)

func main() {
	tunnel := sshtunnel.NewTunnel(&sshtunnel.SshConfig{
		User:         "superwhys",
		HostName:     "remote-server.com:22",
		IdentityFile: "~/.ssh/id_rsa",
	})

	if err := tunnel.Reverse(context.TODO(), "localhost:2222", "10.15.25.23:22"); err != nil {
		panic(err)
	}

	tunnel.Wait()
}
```

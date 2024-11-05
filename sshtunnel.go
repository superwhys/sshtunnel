package sshtunnel

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	lg "github.com/go-puzzles/puzzles/plog"
	uuid "github.com/satori/go.uuid"
)

type SshConfig struct {
	HostName     string
	User         string
	IdentityFile string
}

func (sc *SshConfig) SetDefaults() {
	if sc.IdentityFile == "" {
		sc.IdentityFile = os.Getenv("HOME") + "/.ssh/id_rsa"
	}
	if !strings.Contains(sc.HostName, ":") {
		sc.HostName += ":22"
	}
	if sc.User == "" {
		sc.User = os.Getenv("USER")
	}
}

func getIdentifyKey(filePath string) (ssh.Signer, error) {
	buff, _ := os.ReadFile(filePath)
	return ssh.ParsePrivateKey(buff)
}

func (sc *SshConfig) ParseClientConfig() (*ssh.ClientConfig, error) {
	key, err := getIdentifyKey(sc.IdentityFile)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User: sc.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

type SshTunnel struct {
	confs     []*SshConfig
	sshClient *ssh.Client
	wg        sync.WaitGroup
}

func NewTunnel(cfs ...*SshConfig) *SshTunnel {
	for _, cf := range cfs {
		cf.SetDefaults()
	}

	tunnel := &SshTunnel{
		confs: cfs,
	}
	client, err := tunnel.dial()
	lg.PanicError(err)
	tunnel.sshClient = client
	go tunnel.keepAlive()

	return tunnel
}

func (st *SshTunnel) GetHost() string {
	var resp string
	for _, conf := range st.confs {
		resp = conf.HostName
	}

	return resp
}

func (st *SshTunnel) Close() {
	if st.sshClient != nil {
		st.sshClient.Close()
	}
}

func (st *SshTunnel) Wait() {
	st.wg.Wait()
}

func (st *SshTunnel) GetRemoteHost() string {
	return st.confs[len(st.confs)-1].HostName
}

func (st *SshTunnel) dial() (*ssh.Client, error) {
	clientConf, err := st.confs[0].ParseClientConfig()
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", st.confs[0].HostName, clientConf)
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(st.confs); i++ {
		conf, err := st.confs[i].ParseClientConfig()
		if err != nil {
			return nil, err
		}

		conn, err := client.Dial("tcp", st.confs[i].HostName)
		if err != nil {
			return nil, err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, st.confs[i].HostName, conf)
		if err != nil {
			return nil, err
		}
		client = ssh.NewClient(c, chans, reqs)
	}
	return client, nil
}

func (st *SshTunnel) keepAlive() {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	for range tick.C {
		// send keep alive request
		_, _, err := st.sshClient.SendRequest("keepalive@golang.org", true, nil)
		if err != nil {
			// if error in send request
			// try to reconnect
			if st.sshClient != nil {
				// before retry connection
				// close old connection if exists
				st.sshClient.Close()
			}
			st.sshClient = nil

			for {
				lg.Errorf("ssh connection lost, try to reconnect")
				newClient, err := st.dial()
				if err != nil {
					lg.Errorf("dial ssh server error: %v", err)
					time.Sleep(time.Second * 3)
					continue
				}
				st.sshClient = newClient
				break
			}
		}
	}
}

func (st *SshTunnel) Forward(ctx context.Context, localAddr, remoteAddr string) error {
	st.wg.Add(1)

	// start listen on local addr
	local, err := net.Listen("tcp", localAddr)
	if err != nil {
		return errors.Wrapf(err, "listen on local addr %s", localAddr)
	}

	go func() {
		defer func() {
			lg.Infoc(ctx, "disconnected forwarding %s to %s", localAddr, remoteAddr)
		}()
		defer st.wg.Done()
		defer local.Close()
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			// accept connection from local listener
			client, err := local.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() && netErr.Temporary() {
					// continue if timeout
					continue
				}
				lg.Errorc(ctx, "local accept error: %v, Redialing...", err)
				if local != nil {
					local.Close()
				}
				newLocal, err := net.Listen("tcp", localAddr)
				if err != nil {
					lg.Errorc(ctx, "local listen error: %v", err)
					return
				}
				local = newLocal
				continue
			}

			uid := uuid.NewV4()
			nCtx := lg.With(ctx, "[%v]", uid)
			lg.Infoc(nCtx, "local %s accept connection from %s", client.LocalAddr().String(), client.RemoteAddr().String())

			// dial remote addr and handle local client connections data to remote server
			go func(client net.Conn) {
				defer client.Close()
				if st.sshClient == nil {
					lg.Errorc(nCtx, "lost ssh connection")
					return
				}

				remote, err := st.sshClient.Dial("tcp", remoteAddr)
				if err != nil {
					lg.Errorc(nCtx, "dial remote addr %s error: %v", remoteAddr, err)
					return
				}

				lg.Debugc(nCtx, "start handle local %s connection to remote %s", client.LocalAddr().String(), remoteAddr)
				st.handleClient(nCtx, client, remote)
				lg.Debugc(nCtx, "end handle local %s connection to remote %s", client.LocalAddr().String(), remoteAddr)
			}(client)
		}
	}()
	return nil
}

func (st *SshTunnel) handleClient(ctx context.Context, local, remote net.Conn) {
	defer local.Close()
	defer remote.Close()

	ctx, cancel := context.WithCancel(ctx)

	// remote -> local transfer
	go func() {
		_, err := io.Copy(local, remote)
		if err != nil {
			lg.Warnc(ctx, "remote -> local error: %v", err)
		}
		cancel()
	}()

	// local -> remote transfer
	go func() {
		_, err := io.Copy(remote, local)
		if err != nil {
			lg.Warnc(ctx, "local -> remote error: %v", err)
		}
		cancel()
	}()
	<-ctx.Done()
}

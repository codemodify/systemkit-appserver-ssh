package servers

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	appServer "github.com/codemodify/systemkit-appserver"
	"github.com/codemodify/systemkit-cryptography-gocrypto/ssh"
	"github.com/gorilla/mux"

	logging "github.com/codemodify/systemkit-logging"
)

// SSHTunnelServer -
type SSHTunnelServer struct {
	sshServerConfig *ssh.ServerConfig
	server          appServer.IServer
	router          *mux.Router
}

// NewSSHTunnelServer -
func NewSSHTunnelServer(sshServerConfig *ssh.ServerConfig, server appServer.IServer) appServer.IServer {
	return &SSHTunnelServer{
		sshServerConfig: sshServerConfig,
		server:          server,
		router:          mux.NewRouter(),
	}
}

// Run - Implement `IServer`
func (thisRef *SSHTunnelServer) Run(ipPort string, enableCORS bool) error {

	//
	// BASED-ON: https://godoc.org/github.com/codemodify/systemkit-cryptography/gocrypto/ssh#example-NewServerConn
	//

	listener, err := net.Listen("tcp4", ipPort)
	if err != nil {
		return err
	}

	thisRef.PrepareRoutes(thisRef.router)
	thisRef.RunOnExistingListenerAndRouter(listener, thisRef.router, enableCORS)

	return nil
}

// PrepareRoutes - Implement `IServer`
func (thisRef *SSHTunnelServer) PrepareRoutes(router *mux.Router) {
	thisRef.server.PrepareRoutes(router)
}

// RunOnExistingListenerAndRouter - Implement `IServer`
func (thisRef *SSHTunnelServer) RunOnExistingListenerAndRouter(listener net.Listener, router *mux.Router, enableCORS bool) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			logging.Errorf("JM-SSH: failed to accept incoming connection: %s", err.Error())

			continue
		}

		go thisRef.runSSH(connection)
	}
}

type customResponseWriter struct {
	http.ResponseWriter
	sshChannel ssh.Channel
}

func (thisRef *customResponseWriter) Write(data []byte) (int, error) {
	logging.Tracef("JM-SSH: sending back %d bytes", len(data))

	return thisRef.sshChannel.Write(data)
}

func (thisRef *SSHTunnelServer) runSSH(connection net.Conn) {
	// Before use, a handshake must be performed on the incoming connection
	sshServerConnection, chans, reqs, err := ssh.NewServerConn(connection, thisRef.sshServerConfig)
	if err != nil {
		logging.Errorf("JM-SSH: failed to handshake: %s", err)

		return
	}

	logging.Infof("JM-SSH: Connection %s", sshServerConnection.RemoteAddr().String())

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, _, err := newChannel.Accept()
		if err != nil {
			logging.Errorf("JM-SSH: could not accept channel: %v", err.Error())
			break
		}

		go func(ch ssh.Channel) {
			logging.Tracef("JM-SSH: newChannel.Accept()")

			defer ch.Close()

			for {
				data := make([]byte, 1000000)
				len, err := ch.Read(data)
				if err != nil {
					if strings.Compare(err.Error(), "EOF") == 0 {
						logging.Infof("JM-SSH: TRANSFER-FINISHED: %v", err)
						break
					} else {
						logging.Errorf("JM-SSH: DATA-ERROR: %v", err)
						break
					}
				}

				data = data[0:len]
				logging.Debugf("JM-SSH: DATA-TO-PASS-ON: %s", string(data))

				apiEndpoing := appServer.APIEndpoint{}
				err = json.Unmarshal(data, &apiEndpoing)
				if err != nil {
					logging.Errorf("JM-SSH: Missing ROUTE: %s", err.Error())
				}

				// Make `http.Request`
				request, err := http.NewRequest("POST", apiEndpoing.Value, bytes.NewBuffer(data))
				if err != nil {
					logging.Errorf("JM-SSH: SSH-DATA-ERROR: %s", err.Error())
					break
				}

				route := thisRef.router.Get(apiEndpoing.Value)
				if route == nil {
					logging.Errorf("JM-SSH: Missing ROUTE: %s", apiEndpoing.Value)
					break
				}

				logging.Errorf("JM-SSH: ServeHTTP()")
				route.GetHandler().ServeHTTP(&customResponseWriter{sshChannel: ch}, request)

				break
			}
		}(channel)
	}
}

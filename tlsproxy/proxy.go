package tlsproxy

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"time"
)

var tlsServerConfig *tls.Config
var sslkeylog *os.File

func init() {
	certPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatal(err)
	}
	tlsServerConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	sslkeylog, err = os.OpenFile("/tmp/sslkeylogfile.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalln(err)
	}
}

type clientConn struct {
	conn net.Conn
	buf  []byte
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.conn.Read(b)
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *clientConn) Close() (err error) {
	return c.conn.Close()
}

func (c *clientConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func NewProxy(client, server net.Conn) (net.Conn, net.Conn) {
	var err error = nil
	var n int = 0
	var buf [3]byte
	if n, err = client.Read(buf[:]); err != nil {
		return client, server
	}
	if n != 3 || buf[0] != 22 || buf[1] != 3 || buf[2]>>4 != 0 {
		server.Write(buf[:n])
		return client, server
	}
	newClient := clientConn{
		conn: client,
		buf:  buf[:n],
	}
	//return &newClient, server
	c := tls.Server(&newClient, tlsServerConfig)
	s := tls.Client(server, &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       sslkeylog,
	})
	return c, s
}

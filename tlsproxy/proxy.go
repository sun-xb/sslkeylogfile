package tlsproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/howeyc/gopass"
)

type NewConnection struct {
	conn net.Conn
	buf  []byte
}

func (c *NewConnection) Read(b []byte) (n int, err error) {
	var num int = 0
	if len(c.buf) > 0 {
		num = copy(b, c.buf)
		c.buf = c.buf[num:]
	}
	n, err = c.conn.Read(b[num:])
	n += num
	return
}

func (c *NewConnection) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	return
}

func (c *NewConnection) Close() (err error) {
	return c.conn.Close()
}

func (c *NewConnection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *NewConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *NewConnection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *NewConnection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *NewConnection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type TlsProxy struct {
	sslKeyLogWriter io.Writer
	caCertificate   *x509.Certificate
	caPrivateKey    *rsa.PrivateKey
	privateKey      *rsa.PrivateKey
}

func decryptPemBlock(prompt string, block *pem.Block) error {
	if x509.IsEncryptedPEMBlock(block) {
		fmt.Print(prompt)
		passwd, err := gopass.GetPasswd()
		if err != nil {
			return err
		}
		data, err := x509.DecryptPEMBlock(block, []byte(passwd))
		if err != nil {
			return err
		}
		block.Bytes = data
	}
	return nil
}

func NewTlsProxy(w io.Writer, caCertificate, caPrivateKey []byte) *TlsProxy {
	tp := &TlsProxy{
		sslKeyLogWriter: w,
	}
	var err error

	tp.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalln(err)
	}

	caCertBlock, _ := pem.Decode(caCertificate)
	if err = decryptPemBlock("cacert password: ", caCertBlock); err != nil {
		log.Fatalln(err)
	}
	tp.caCertificate, err = x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Fatalln(err)
	}

	caKeyBlock, _ := pem.Decode(caPrivateKey)
	if err = decryptPemBlock("cakey password: ", caKeyBlock); err != nil {
		log.Fatalln(err)
	}
	tp.caPrivateKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		log.Fatalln(err)
	}

	return tp
}

func (t *TlsProxy) Proxy(conn net.Conn, host string) (err error, c, s net.Conn) {
	var n int
	var magic [3]byte

	remote, err := t.connectRemote(host)
	if err != nil {
		return err, nil, nil
	}
	if n, err = conn.Read(magic[:]); err != nil {
		return nil, conn, remote
	}
	newConn := &NewConnection{
		conn: conn,
		buf:  magic[:n],
	}

	if n != 3 || magic[0] != 22 || magic[1] != 3 || magic[2]>>4 != 0 {
		return nil, newConn, remote
	}
	tlsServer := tls.Client(remote, &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       t.sslKeyLogWriter,
	})
	if err = tlsServer.Handshake(); err != nil {
		remote.Close()
		if remote, err = t.connectRemote(host); err != nil {
			return err, nil, nil
		}
		return nil, newConn, remote
	}

	cert, err := t.generateCert(tlsServer.ConnectionState().PeerCertificates[0])
	if err != nil {
		log.Println("create certificate failed:", err)
		return nil, newConn, remote
	}
	tlsClient := tls.Server(newConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	return nil, tlsClient, tlsServer
}

func (t *TlsProxy) generateCert(remoteCert *x509.Certificate) (tls.Certificate, error) {
	tlsCert := tls.Certificate{}
	tlsCert.PrivateKey = t.privateKey
	cert, err := x509.CreateCertificate(rand.Reader, remoteCert, t.caCertificate, t.privateKey.Public(), t.caPrivateKey)
	if err != nil {
		return tlsCert, err
	}
	tlsCert.Certificate = append(tlsCert.Certificate, cert)
	return tlsCert, nil
}

func (t *TlsProxy) connectRemote(host string) (net.Conn, error) {
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return nil, err
	}
	return remote, nil
}

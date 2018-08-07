package ldap

import (
	"net"
	"gopkg.in/ldap.v2"
	"github.com/tjfoc/gmtls"
)

// DialTLS connects to the given address on the given network using tls.Dial
// and then returns a new Conn for the connection.
func DialTLS(network, addr string, config *gmtls.Config) (*ldap.Conn, error) {
	dc, err := net.DialTimeout(network, addr, ldap.DefaultTimeout)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}
	c := gmtls.Client(dc, config)
	err = c.Handshake()
	if err != nil {
		// Handshake error, close the established connection before we return an error
		dc.Close()
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}
	conn := ldap.NewConn(c, true)
	conn.Start()
	return conn, nil
}
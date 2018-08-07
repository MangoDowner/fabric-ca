package mysql

import (
	"strings"
	"fmt"
	"github.com/tjfoc/gmtls"
)

var (
	tlsConfigRegister map[string]*gmtls.Config // Register for custom tls.Configs
)


// Returns the bool value of the input.
// The 2nd return value indicates if the input was a valid bool value
func readBool(input string) (value bool, valid bool) {
	switch input {
	case "1", "true", "TRUE", "True":
		return true, true
	case "0", "false", "FALSE", "False":
		return false, true
	}

	// Not a valid bool value
	return
}

// RegisterTLSConfig registers a custom tls.Config to be used with sql.Open.
// Use the key as a value in the DSN where tls=value.
//
//  rootCertPool := x509.NewCertPool()
//  pem, err := ioutil.ReadFile("/path/ca-cert.pem")
//  if err != nil {
//      log.Fatal(err)
//  }
//  if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
//      log.Fatal("Failed to append PEM.")
//  }
//  clientCert := make([]tls.Certificate, 0, 1)
//  certs, err := tls.LoadX509KeyPair("/path/client-cert.pem", "/path/client-key.pem")
//  if err != nil {
//      log.Fatal(err)
//  }
//  clientCert = append(clientCert, certs)
//  mysql.RegisterTLSConfig("custom", &tls.Config{
//      RootCAs: rootCertPool,
//      Certificates: clientCert,
//  })
//  db, err := sql.Open("mysql", "user@tcp(localhost:3306)/test?tls=custom")
//
func RegisterTLSConfig(key string, config *gmtls.Config) error {
	if _, isBool := readBool(key); isBool || strings.ToLower(key) == "skip-verify" {
		return fmt.Errorf("key '%s' is reserved", key)
	}

	if tlsConfigRegister == nil {
		tlsConfigRegister = make(map[string]*gmtls.Config)
	}

	tlsConfigRegister[key] = config
	return nil
}

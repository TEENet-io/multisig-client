package multisig_client

import (
	"os"
	"testing"
)

var connConfig = ConnectorConfig{
	UserID:        0,
	Name:          "client0",
	Cert:          "config/data/client0.crt",
	Key:           "config/data/client0.key",
	CaCert:        "config/data/client0-ca.crt",
	ServerAddress: "52.184.81.32:6001",
	ServerCACert:  "config/data/node0-ca.crt",
}

func setupConn(connConfig ConnectorConfig) (*Connector, error) {
	if _, err := os.Stat(connConfig.Cert); os.IsNotExist(err) {
		return nil, err
	}
	if _, err := os.Stat(connConfig.Key); os.IsNotExist(err) {
		return nil, err
	}
	if _, err := os.Stat(connConfig.CaCert); os.IsNotExist(err) {
		return nil, err
	}
	if _, err := os.Stat(connConfig.ServerCACert); os.IsNotExist(err) {
		return nil, err
	}
	c, err := NewConnector(&connConfig)
	return c, err
}

func TestSignAndVerify2(t *testing.T) {
	c, err := setupConn(connConfig)
	if err != nil {
		t.Fatalf("Error setting up connector: %v", err)
	}
	defer c.Close()

	ss := NewRemoteSchnorrSigner(c)

	message := []byte("hello world")
	msgHash, sig, err := ss.Sign(message)
	if err != nil {
		t.Fatalf("Error signing: %v", err)
	}

	pubKey, err := ss.Pub()
	if err != nil {
		t.Fatalf("Error getting public key: %v", err)
	}

	t.Logf("Group Public Key: %v\n", pubKey)

	ok := sig.Verify(msgHash, pubKey)
	if !ok {
		t.Fatalf("Signature verification failed")
	}
}

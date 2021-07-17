package main
import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func printKey(key *ecdsa.PrivateKey) {
	var x = base64.StdEncoding.EncodeToString(key.PublicKey.X.Bytes())
	var y = base64.StdEncoding.EncodeToString(key.PublicKey.Y.Bytes())
	var d = base64.StdEncoding.EncodeToString(key.D.Bytes())
	var jwk, _ = json.Marshal(map[string]string {
		"kty": "EC",
		"crv": "P-256",
		"x": x,
		"y": y,
		"d": d,
	})
	fmt.Printf("Private key in JWK format:\n%s\n", jwk)
	fmt.Printf("Private key in base64 format:\n%s\n", d)
}

func main() {
	text, _ := ioutil.ReadAll(os.Stdin)
	for len(text) > 0 {
		var block *pem.Block
		block, text = pem.Decode(text)
		key, _ := x509.ParseECPrivateKey(block.Bytes)
		if key != nil {
			printKey(key);
		}
	}
}

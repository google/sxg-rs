package main
import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
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
	fmt.Println(string(jwk))
}

func main() {
	text, _ := ioutil.ReadFile("privkey.pem")
	for len(text) > 0 {
		var block *pem.Block
		block, text = pem.Decode(text)
		key, _ := x509.ParseECPrivateKey(block.Bytes)
		if key != nil {
			printKey(key);
		}
	}
}

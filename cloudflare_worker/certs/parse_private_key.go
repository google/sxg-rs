package main
import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)
func main() {
	text, _ := ioutil.ReadFile("privkey.pem")
	for len(text) > 0 {
		var block *pem.Block
		block, text = pem.Decode(text)
		key, _ := x509.ParseECPrivateKey(block.Bytes)
		if key != nil {
			fmt.Println(base64.StdEncoding.EncodeToString(key.D.Bytes()))
		}
	}
}

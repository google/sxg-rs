// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main
import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	text, err := ioutil.ReadAll(io.LimitReader(os.Stdin, 4194304))
	if err != nil {
		panic("Error reading input: " + err.Error())
	}
	for len(text) > 0 {
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil {
			break
		}
		key, _ := x509.ParseECPrivateKey(block.Bytes)
		if key != nil {
			printKey(key)
			return
		}
	}
	fmt.Println("No matching private key was found. The PEM file should include the lines:")
	fmt.Println("-----BEGIN EC PRIVATE KEY-----")
	fmt.Println("and")
	fmt.Println("-----END EC PRIVATE KEY-----")
}

// Copyright 2026 Jeremiah Jordan
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

// Independently encode canonical numeric XML with OVH's KMIP implementation.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	_ "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"
	"os"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	r := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := r.Token()
		if err != nil {
			panic(err)
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "KMIP" {
			break
		}
	}
	d, err := ttlv.NewXMLFromDecoder(r)
	if err != nil {
		panic(err)
	}
	for d.Tag() != 0 {
		var v ttlv.Value
		if err := v.DecodeTTLV(&d); err != nil {
			panic(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(ttlv.MarshalTTLV(v)))
	}
}

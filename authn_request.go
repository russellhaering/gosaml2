// Copyright 2016 Russell Haering et al.
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

package saml2

import (
	"time"
)

// AuthNRequest is the go struct representation of an authentication request
type AuthNRequest struct {
	ID                          string    `xml:",attr"`
	Version                     string    `xml:",attr"`
	ProtocolBinding             string    `xml:",attr"`
	AssertionConsumerServiceURL string    `xml:",attr"`
	IssueInstant                time.Time `xml:",attr"`
	Destination                 string    `xml:",attr"`

	Issuer Issuer `xml:"Issuer"`
}

type Issuer struct {
	SPProvidedID string `xml:",attr"`
	Value        string `xml:",chardata"`
}

type Signature struct {
	SignedInfo     SignedInfo `xml:"SignedInfo"`
	SignatureValue string     `xml:"SignatureValue"`
	KeyInfo        KeyInfo    `xml:"KeyInfo"`
}

type SignedInfo struct {
	Reference Reference `xml:"Reference"`
}

type Reference struct {
	URI         string `xml:",attr"`
	DigestValue string `xml:"DigestValue"`
}

type KeyInfo struct {
	KeyName string `xml:"KeyName"`
}

type X509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type Extensions struct {
	Picker Picker `xml:"picker:Picker"`
}

type Picker struct {
	Value string `xml:",chardata"`
}

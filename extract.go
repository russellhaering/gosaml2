// Copyright 2025 Russell Haering et al.
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
	"encoding/xml"
	"fmt"
	"time"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

// LogoutRequestFromElement extracts a LogoutRequest from a
// samlp:LogoutRequest element.
func LogoutRequestFromElement(el *xmltree.Element) (*LogoutRequest, error) {
	if el == nil || el.Tag != "LogoutRequest" {
		tag := "<nil>"
		if el != nil {
			tag = el.Tag
		}
		return nil, fmt.Errorf("saml: expected element LogoutRequest, got %s", tag)
	}

	req := &LogoutRequest{
		XMLName:      xml.Name{Space: SAMLProtocolNamespace, Local: "LogoutRequest"},
		ID:           el.SelectAttrValue("ID", ""),
		Version:      el.SelectAttrValue("Version", ""),
		NotOnOrAfter: el.SelectAttrValue("NotOnOrAfter", ""),
		Destination:  el.SelectAttrValue("Destination", ""),
	}

	if v := el.SelectAttrValue("IssueInstant", ""); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("saml: invalid IssueInstant timestamp: %v", err)
		}
		req.IssueInstant = ts
	}

	issuer, err := el.SingleElement("Issuer")
	if err != nil {
		return nil, err
	}
	if issuer != nil {
		req.Issuer = &types.Issuer{
			XMLName: xml.Name{Space: SAMLAssertionNamespace, Local: "Issuer"},
			Value:   issuer.Text(),
		}
	}
	nameID, err := el.SingleElement("NameID")
	if err != nil {
		return nil, err
	}
	if nameID != nil {
		req.NameID = &types.NameID{
			XMLName: xml.Name{Space: SAMLAssertionNamespace, Local: "NameID"},
			Format:  nameID.SelectAttrValue("Format", ""),
			Value:   nameID.Text(),
		}
	}
	return req, nil
}

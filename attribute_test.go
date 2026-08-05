// Copyright 2026 Russell Haering et al.
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
	"testing"

	"github.com/russellhaering/gosaml2/types"
	"github.com/stretchr/testify/require"
)

const nameIDAttributeStatement = `
<saml2:AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
	<saml2:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" FriendlyName="eduPersonTargetedID">
		<saml2:AttributeValue>
			<saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
				NameQualifier="https://idp.example.edu/idp/shibboleth"
				SPNameQualifier="https://sp.example.com/shibboleth">a1b2c3d4e5f6</saml2:NameID>
		</saml2:AttributeValue>
	</saml2:Attribute>
	<saml2:Attribute Name="Email">
		<saml2:AttributeValue>phoebe.simon@scaleft.com</saml2:AttributeValue>
	</saml2:Attribute>
</saml2:AttributeStatement>`

func TestValuesWithNameIDAttributeValue(t *testing.T) {
	statement := &types.AttributeStatement{}
	err := xml.Unmarshal([]byte(nameIDAttributeStatement), statement)
	require.NoError(t, err)

	vals := make(Values)
	for _, attribute := range statement.Attributes {
		vals[attribute.Name] = attribute
	}

	// A NameID-valued attribute yields the NameID's value from Get and GetAll.
	require.Equal(t, "a1b2c3d4e5f6", vals.Get("urn:oid:1.3.6.1.4.1.5923.1.1.1.10"))
	require.Equal(t, []string{"a1b2c3d4e5f6"}, vals.GetAll("urn:oid:1.3.6.1.4.1.5923.1.1.1.10"))

	// Plain text attributes are unaffected.
	require.Equal(t, "phoebe.simon@scaleft.com", vals.Get("Email"))
	require.Equal(t, []string{"phoebe.simon@scaleft.com"}, vals.GetAll("Email"))

	// The nested NameID and its qualifiers are accessible directly.
	nameID := statement.Attributes[0].Values[0].NameID
	require.NotNil(t, nameID)
	require.Equal(t, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", nameID.Format)
	require.Equal(t, "https://idp.example.edu/idp/shibboleth", nameID.NameQualifier)
	require.Equal(t, "https://sp.example.com/shibboleth", nameID.SPNameQualifier)
	require.Equal(t, "a1b2c3d4e5f6", nameID.Value)
}

package saml2

import (
	"io"
	"os"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestArtifact(t *testing.T) {
	spURL := "https://sp.test"
	randomKeyStore := dsig.RandomKeyStoreForTest()
	sp := SAMLServiceProvider{
		AssertionConsumerServiceURL: spURL,
		AudienceURI:                 spURL,
		ServiceProviderIssuer:       spURL,
		IdentityProviderSSOURL:      "https://idp.test/saml/sso",
		SignAuthnRequests:           true,
		SPKeyStore:                  randomKeyStore,
	}
	req, err := sp.buildResolveRequest("1234567")
	if err != nil {
		t.Fatal(err)
	}

	doc := etree.NewDocument()
	_, err = doc.ReadFrom(req)
	require.NoError(t, err)

	// Make sure request is signed
	el := doc.FindElement("./Envelope/Body/ArtifactResolve/Signature")
	require.NotNil(t, el)
	// Make sure artifact is set
	el = doc.FindElement("./Envelope/Body/ArtifactResolve/Artifact")
	require.NotNil(t, el)
	require.Equal(t, "1234567", el.Text())
	io.Copy(os.Stdout, req)
}

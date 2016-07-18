package saml2

import dsig "github.com/russellhaering/goxmldsig"

const issueInstantFormat = "2006-01-02T15:04:05Z"

type SAMLServiceProvider struct {
	IdentityProviderSSOURL      string
	IdentityProviderIssuer      string
	AssertionConsumerServiceURL string
	SignAuthnRequests           bool
	SignAuthnRequestsAlgorithm  dsig.SignatureAlgorithm
	AudienceURI                 string
	IDPCertificateStore         dsig.X509CertificateStore
	SPKeyStore                  dsig.X509KeyStore
	NameIdFormat                string
	SkipSignatureValidation     bool
	IsOkta                      bool
}

func (sp *SAMLServiceProvider) SigningContext() *dsig.SigningContext {
	return dsig.NewDefaultSigningContext(sp.SPKeyStore)
}

type ProxyRestriction struct {
	Count    int
	Audience []string
}

type WarningInfo struct {
	OneTimeUse       bool
	ProxyRestriction *ProxyRestriction
	NotInAudience    bool
	InvalidTime      bool
}

type AssertionInfo struct {
	NameID      string
	Values      Values
	WarningInfo *WarningInfo
}

func childPath(space, tag string) string {
	if space == "" {
		return "./" + tag
	}
	return "./" + space + ":" + tag
}

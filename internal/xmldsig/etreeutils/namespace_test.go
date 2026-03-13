package etreeutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultNSContextDefaultPrefix(t *testing.T) {
	// Regression test for #29: the default prefix should resolve to ""
	// (no namespace), not the XML namespace.
	ctx := NewDefaultNSContext()
	ns, err := ctx.LookupPrefix("")
	require.NoError(t, err)
	require.Equal(t, "", ns)
}

func TestDefaultNSContextXmlPrefix(t *testing.T) {
	ctx := NewDefaultNSContext()
	ns, err := ctx.LookupPrefix("xml")
	require.NoError(t, err)
	require.Equal(t, XMLNamespace, ns)
}

func TestDefaultNSContextXmlnsPrefix(t *testing.T) {
	ctx := NewDefaultNSContext()
	ns, err := ctx.LookupPrefix("xmlns")
	require.NoError(t, err)
	require.Equal(t, XMLNSNamespace, ns)
}

func TestDefaultNSContextUndeclaredPrefix(t *testing.T) {
	ctx := NewDefaultNSContext()
	_, err := ctx.LookupPrefix("undeclared")
	require.ErrorAs(t, err, &ErrUndeclaredNSPrefix{})
}

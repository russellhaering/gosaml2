package xmldsig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

// TestC14NGolden_MatchesEtreePipeline is the differential gate for the
// etree→xmltree port: testdata/c14n_golden holds exclusive-c14n outputs
// produced by the pre-port, etree-based pipeline over the real-world corpus
// (tools/gen-c14n-golden, since removed). The ported pipeline must
// reproduce every one byte-for-byte.
//
// Corpus documents containing CR bytes were excluded at generation time:
// the strict parser performs XML §2.11 line-ending normalization that the
// etree pipeline did not, legitimately changing their canonical form.
func TestC14NGolden_MatchesEtreePipeline(t *testing.T) {
	goldens, err := filepath.Glob("testdata/c14n_golden/*.c14n")
	require.NoError(t, err)
	require.NotEmpty(t, goldens, "golden corpus missing")

	matched := 0
	for _, goldenPath := range goldens {
		expected, err := os.ReadFile(goldenPath)
		require.NoError(t, err)

		// Golden names are <dir>_<file>.c14n over testdata/corpus/<dir>/<file>
		// or testdata_<file>.c14n over testdata/<file>.
		name := strings.TrimSuffix(filepath.Base(goldenPath), ".c14n")
		dir, file, ok := strings.Cut(name, "_")
		require.True(t, ok, name)
		var srcPath string
		if dir == "testdata" {
			srcPath = filepath.Join("../../testdata", file)
		} else {
			srcPath = filepath.Join("../../testdata/corpus", dir, file)
		}
		src, err := os.ReadFile(srcPath)
		require.NoError(t, err, "source document for golden %s", name)

		var doc *xmltree.Document
		if strings.Contains(strings.ToLower(file), "metadata") {
			doc, err = xmltree.ParseMetadata(src)
		} else {
			doc, err = xmltree.Parse(src)
		}
		require.NoError(t, err, "%s", srcPath)

		canon, err := MakeC14N10ExclusiveCanonicalizerWithPrefixList("").
			Canonicalize(doc.Root())
		require.NoError(t, err, "%s", srcPath)

		require.Equal(t, string(expected), string(canon),
			"%s: canonical output diverges from the etree pipeline", srcPath)
		matched++
	}
	t.Logf("byte-identical c14n output for %d corpus documents", matched)
}

package golang

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FindConflicts(t *testing.T) {
	ctx := context.Background()
	versionMgr := New()
	versionMgr.Init(ctx, "./test-fixtures", "")
	conflicts, err := versionMgr.FindConflicts(ctx)
	require.NoError(t, err)
	assert.Equal(t, 32, len(conflicts))
}

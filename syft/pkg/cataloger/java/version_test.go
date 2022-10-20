package java

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_GetReleaseTime(t *testing.T) {
	ctx := context.Background()
	depName := "com.google.inject/guice"
	expectedTime, err := time.Parse(timeFormat, "2022-01-24 22:06")
	assert.Nil(t, err)

	version := NewMaven()
	versionMap, err := version.GetReleaseTime(ctx, depName, "5.1.0", "5.0.1", "5.0.0")
	assert.Nil(t, err)
	assert.Equal(t, versionMap["5.1.0"], expectedTime)
}

func Test_parseDependencyConvergence(t *testing.T) {
	output := `[WARNING] 
Dependency convergence error for com.google.api:api-common:jar:1.8.1:compile paths to dependency are:
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core:jar:1.90.0:compile
      +-com.google.api:gax:jar:1.48.1:compile
        +-com.google.api:api-common:jar:1.8.1:compile
and
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core:jar:1.90.0:compile
      +-com.google.api.grpc:proto-google-iam-v1:jar:0.12.0:compile
        +-com.google.api:api-common:jar:1.5.0:compile
and
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core-http:jar:1.90.0:compile
      +-com.google.api:gax-httpjson:jar:0.65.1:compile
        +-com.google.api:api-common:jar:1.8.1:compile
and
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core-grpc:jar:1.90.0:compile
      +-com.google.api:gax-grpc:jar:1.48.1:compile
        +-com.google.api:api-common:jar:1.8.1:compile
and
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.api.grpc:proto-google-cloud-translate-v3beta1:jar:0.73.0:compile
      +-com.google.api:api-common:jar:1.8.1:compile

[WARNING] 
Dependency convergence error for com.google.http-client:google-http-client-jackson2:jar:1.31.0:compile paths to dependency are:
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core-http:jar:1.90.0:compile
      +-com.google.auth:google-auth-library-oauth2-http:jar:0.17.1:compile
        +-com.google.http-client:google-http-client-jackson2:jar:1.31.0:compile
and
+-com.example.deps.example1:example1-simple:jar:1.0-SNAPSHOT
  +-com.google.cloud:google-cloud-translate:jar:1.90.0:compile
    +-com.google.cloud:google-cloud-core-http:jar:1.90.0:compile
      +-com.google.api-client:google-api-client:jar:1.30.2:compile
        +-com.google.http-client:google-http-client-jackson2:jar:1.30.1:compile
[ERROR] Rule 0: org.apache.maven.plugins.enforcer.DependencyConvergence failed with message:
Failed while enforcing releasability. See above detailed error message.
`

	convergence := strings.NewReader(output)
	conflicts, err := parseDependencyConvergence(bufio.NewScanner(convergence))
	assert.Nil(t, err)
	assert.Equal(t, len(conflicts), 2)
}

package main

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOffRegistryRedirect(t *testing.T) {
	redirect := func(t *testing.T, location string) error {
		t.Helper()
		target, err := url.Parse(location)
		require.NoError(t, err)

		return offRegistryRedirect(&http.Request{URL: target}, nil)
	}

	require.NoError(t, redirect(t, "https://registry.npmjs.org/ssri/-/ssri-13.0.1.tgz"),
		"the registry may hand a distribution on within itself")

	for _, location := range []string{
		"https://evil.example.com/ssri-13.0.1.tgz",
		"http://registry.npmjs.org/ssri/-/ssri-13.0.1.tgz",
		"https://registry.npmjs.org.evil.example.com/ssri-13.0.1.tgz",
	} {
		require.ErrorContains(t, redirect(t, location), "is not the registry the lockfile pins", location)
	}
}

#!/bin/sh
exec "$CLEANUP_HELPER_BINARY" -test.run=^TestCleanupBackendProcess$ -- "$@"
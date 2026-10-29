package nativegate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/import_server"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/stapel"
)

const (
	rsyncOracleProbeTimeout = 15 * time.Second
	rsyncOracleReadyTimeout = 5 * time.Second
	rsyncOracleRunTimeout   = 2 * time.Minute
	rsyncOraclePort         = "1873"
	// The source tree is served from a mount the daemon chroots into, so the paths the
	// filters are matched against are the paths of the source image, as in a build.
	rsyncOracleModulePath  = "/src"
	rsyncOracleTargetMount = "/dst"
)

// runRsyncImport performs the import the way the legacy Stapel builder performs it: the
// rsync of the stapel image serves the source tree as the import module, and the copy is
// the command the import server builds, filters included.
func runRsyncImport(ctx context.Context, sourceRoot, targetRoot string, scope ImportScope) {
	requireRsyncOracle(ctx)

	runtimeDir := ginkgo.GinkgoT().TempDir()
	confPath := filepath.Join(runtimeDir, "rsyncd.conf")
	secretsPath := filepath.Join(runtimeDir, "rsyncd.secrets")
	authUser, authPassword := "werf-oracle", "oracle-password"
	gomega.Expect(os.WriteFile(confPath, []byte(rsyncOracleDaemonConf(authUser)), 0o644)).To(gomega.Succeed())
	gomega.Expect(os.WriteFile(secretsPath, []byte(fmt.Sprintf("%s:%s\n", authUser, authPassword)), 0o600)).To(gomega.Succeed())

	srv := &import_server.RsyncServer{
		IPAddress:    "127.0.0.1",
		Port:         rsyncOraclePort,
		AuthUser:     authUser,
		AuthPassword: authPassword,
	}
	copyCommand := srv.GetCopyCommand(ctx, &config.Import{Export: &config.Export{ExportBase: &config.ExportBase{
		Add:          rootedImportPath(scope.FromPath),
		To:           path.Join(rsyncOracleTargetMount, rootedImportPath(scope.ToPath)),
		IncludePaths: scope.IncludePaths,
		ExcludePaths: scope.ExcludePaths,
	}}})

	script := fmt.Sprintf("%s && %s", rsyncOracleDaemonScript(srv), copyCommand)
	// The container outlives a killed docker CLI, so it is removed by the identity this
	// run wrote down rather than left to --rm.
	cidPath := filepath.Join(runtimeDir, "container.id")
	ginkgo.DeferCleanup(func(cleanup ginkgo.SpecContext) {
		removeRsyncOracleContainer(cleanup, cidPath)
	})
	run, cancel := context.WithTimeout(ctx, rsyncOracleRunTimeout)
	defer cancel()
	command := exec.CommandContext(run, "docker", "run", "--rm",
		"--cidfile", cidPath,
		"--volume", sourceRoot+":"+rsyncOracleModulePath+":ro",
		"--volume", targetRoot+":"+rsyncOracleTargetMount,
		"--volume", confPath+":/.werf/rsyncd.conf",
		"--volume", secretsPath+":/.werf/rsyncd.secrets",
		"--entrypoint", stapel.BashBinPath(),
		stapel.ImageName(), "-c", script)
	output, err := command.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "rsync import oracle: %s", output)
}

// rsyncOracleDaemonScript starts the import daemon and waits for it to serve the module,
// asking the daemon itself instead of trusting it to be up by the time the copy runs.
func rsyncOracleDaemonScript(srv *import_server.RsyncServer) string {
	return fmt.Sprintf(`%s --daemon --config=/.werf/rsyncd.conf && export RSYNC_PASSWORD='%s' && deadline=$((SECONDS+%d)) && ready=0 && while [ $SECONDS -lt $deadline ]; do if %s rsync://%s@%s:%s/import/ >/dev/null 2>&1; then ready=1; break; fi; done && [ $ready -eq 1 ]`,
		stapel.RsyncBinPath(), srv.AuthPassword, int(rsyncOracleReadyTimeout/time.Second),
		stapel.RsyncBinPath(), srv.AuthUser, srv.IPAddress, srv.Port)
}

func rsyncOracleDaemonConf(authUser string) string {
	return fmt.Sprintf(`pid file = /.werf/rsyncd.pid
lock file = /.werf/rsyncd.lock
log file = /.werf/rsyncd.log
uid = 0
gid = 0
port = %s

[import]
path = %s
read only = true
timeout = 300
auth users = %s
secrets file = /.werf/rsyncd.secrets
strict modes = false
exclude = %s
`, rsyncOraclePort, rsyncOracleModulePath, authUser, strings.Join(import_server.SystemExcludeDirs(), " "))
}

func removeRsyncOracleContainer(ctx context.Context, cidPath string) {
	id, err := os.ReadFile(cidPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	container := strings.TrimSpace(string(id))
	if container == "" {
		return
	}

	deadline, cancel := context.WithTimeout(context.WithoutCancel(ctx), rsyncOracleProbeTimeout)
	defer cancel()
	if output, err := exec.CommandContext(deadline, "docker", "container", "inspect", container).CombinedOutput(); err != nil {
		gomega.Expect(string(output)).To(gomega.ContainSubstring("No such container"), "inspect the rsync import oracle container: %s", output)

		return
	}

	output, err := exec.CommandContext(deadline, "docker", "rm", "--force", container).CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "remove the rsync import oracle container: %s", output)
}

func requireRsyncOracle(ctx context.Context) {
	probe, cancel := context.WithTimeout(ctx, rsyncOracleProbeTimeout)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		ginkgo.Skip("the rsync import oracle needs docker to run the stapel rsync")
	}
	if output, err := exec.CommandContext(probe, "docker", "image", "inspect", stapel.ImageName()).CombinedOutput(); err != nil {
		ginkgo.Skip(fmt.Sprintf("the rsync import oracle needs a local %s image: %s", stapel.ImageName(), output))
	}
}

var _ = ginkgo.Describe("importing original matches over rsync", func() {
	ginkgo.It("leaves an excluded path the target already holds byte for byte unbound", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/keep/one.txt", "one-bytes"),
				treeFile("opt/app/keep/secret/hidden.txt", "hidden-bytes"),
				treeFile("opt/app/drop/two.txt", "two-bytes"),
			},
			// An earlier stage left the same bytes where this import is excluded from writing.
			target: []treeEntry{treeFile("dest/keep/secret/hidden.txt", "hidden-bytes")},
			matches: originalMatches{
				"/opt/app/keep/one.txt":           {{Source: "src", Path: "keep/one.txt"}},
				"/opt/app/keep/secret/hidden.txt": {{Source: "src", Path: "keep/secret/hidden.txt"}},
				"/opt/app/drop/two.txt":           {{Source: "src", Path: "drop/two.txt"}},
			},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				IncludePaths: []string{"keep"},
				ExcludePaths: []string{"keep/secret"},
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/keep/one.txt": {{Source: "src", Path: "keep/one.txt"}},
		}))
	})

	ginkgo.It("leaves nothing of an excluded path at a destination that never held it", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/lib/libx.so", "libx-bytes"),
				treeFile("opt/app/lib/private/key.pem", "key-bytes"),
			},
			matches: originalMatches{
				"/opt/app/lib/libx.so":         {{Source: "src", Path: "lib/libx.so"}},
				"/opt/app/lib/private/key.pem": {{Source: "src", Path: "lib/private/key.pem"}},
			},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				IncludePaths: []string{"lib"},
				ExcludePaths: []string{"lib/private"},
			},
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.ReadFile(filepath.Join(targetRoot, "dest/lib/libx.so"))).To(gomega.Equal([]byte("libx-bytes")))
				_, err := os.Lstat(filepath.Join(targetRoot, "dest/lib/private"))
				gomega.Expect(err).To(gomega.MatchError(os.ErrNotExist))
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/lib/libx.so": {{Source: "src", Path: "lib/libx.so"}},
		}))
	})

	ginkgo.It("leaves an excluded path named in non-ASCII bytes unbound", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/при/keep/ключ.pem", "key-bytes"),
				treeFile("opt/при/keep/pub.so", "pub-bytes"),
			},
			// An earlier stage left the same bytes where this import is excluded from writing.
			target: []treeEntry{treeFile("dest/keep/ключ.pem", "key-bytes")},
			matches: originalMatches{
				"/opt/при/keep/ключ.pem": {{Source: "src", Path: "keep/ключ.pem"}},
				"/opt/при/keep/pub.so":   {{Source: "src", Path: "keep/pub.so"}},
			},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/при",
				ToPath:       "/dest",
				ExcludePaths: []string{"keep/ключ.pem"},
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/keep/pub.so": {{Source: "src", Path: "keep/pub.so"}},
		}))
	})

	ginkgo.It("refuses an import source the copy follows through a symlink", func(ctx ginkgo.SpecContext) {
		_, err := importCase{
			source: []treeEntry{
				treeFile("opt/real/tool", "tool-bytes"),
				treeLink("opt/app", "real"),
			},
			matches: originalMatches{"/opt/real/tool": {{Source: "src", Path: "bin/tool"}}},
			scope:   ImportScope{Backend: ImportBackendRsync, FromPath: "/opt/app", ToPath: "/dest"},
			// Unlike the subtree copy, rsync stats the source through the link and carries
			// what it names, so an empty answer here would be a lie.
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.ReadFile(filepath.Join(targetRoot, "dest/tool"))).To(gomega.Equal([]byte("tool-bytes")))
			},
		}.run(ctx)

		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("carries a top-level file import the include paths do not name", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source:  []treeEntry{treeFile("opt/tool", "tool-bytes")},
			target:  []treeEntry{treeDir("dest")},
			matches: originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/tool",
				ToPath:       "/dest",
				IncludePaths: []string{"inner"},
				ExcludePaths: []string{"other"},
			},
			// The filters are written below a path that holds no tree, so none of them
			// matches the file itself and rsync carries it.
			afterCopy: func(targetRoot string) {
				gomega.Expect(os.ReadFile(filepath.Join(targetRoot, "dest/tool"))).To(gomega.Equal([]byte("tool-bytes")))
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/tool": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	ginkgo.It("refuses a filter this gate does not read instead of reading it as another", func(ctx ginkgo.SpecContext) {
		source := treeIndex(ctx, treeRoot([]treeEntry{treeFile("opt/app/tool", "tool-bytes")}))
		target := treeIndex(ctx, treeRoot(nil))
		matches := originalMatches{"/opt/app/tool": {{Source: "src", Path: "bin/tool"}}}

		for _, exclude := range []string{"a***b", `a\*b`, "[[:alpha:]]"} {
			_, err := importOriginalMatches(ctx, source, matches, target, target, ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				ExcludePaths: []string{exclude},
			})
			gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")), "exclude %q", exclude)
		}
	})

	ginkgo.It("keeps an excluded child out of an explicitly included directory", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/lib/libx.so", "libx-bytes"),
				treeFile("opt/app/lib/private/key.pem", "key-bytes"),
				treeFile("opt/app/lib/private/notes.txt", "notes-bytes"),
			},
			target: []treeEntry{treeFile("dest/lib/private/key.pem", "key-bytes")},
			matches: originalMatches{
				"/opt/app/lib/libx.so":           {{Source: "src", Path: "lib/libx.so"}},
				"/opt/app/lib/private/key.pem":   {{Source: "src", Path: "lib/private/key.pem"}},
				"/opt/app/lib/private/notes.txt": {{Source: "src", Path: "lib/private/notes.txt"}},
			},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				IncludePaths: []string{"lib"},
				ExcludePaths: []string{"lib/private"},
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/lib/libx.so": {{Source: "src", Path: "lib/libx.so"}},
		}))
	})

	ginkgo.It("prunes the directories a glob exclude names", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/bin/tool", "tool-bytes"),
				treeFile("opt/app/var/cache/one/blob", "one-bytes"),
				treeFile("opt/app/var/cache/two/blob", "two-bytes"),
				treeFile("opt/app/var/keep.txt", "keep-bytes"),
			},
			target: []treeEntry{treeFile("dest/var/cache/two/blob", "two-bytes")},
			matches: originalMatches{
				"/opt/app/bin/tool":           {{Source: "src", Path: "bin/tool"}},
				"/opt/app/var/cache/one/blob": {{Source: "src", Path: "var/cache/one/blob"}},
				"/opt/app/var/cache/two/blob": {{Source: "src", Path: "var/cache/two/blob"}},
				"/opt/app/var/keep.txt":       {{Source: "src", Path: "var/keep.txt"}},
			},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				ExcludePaths: []string{"var/cache/*"},
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/bin/tool":     {{Source: "src", Path: "bin/tool"}},
			"/dest/var/keep.txt": {{Source: "src", Path: "var/keep.txt"}},
		}))
	})

	ginkgo.It("prunes what a double-star exclude names at any depth", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/lib/a/pub.so", "pub-bytes"),
				treeFile("opt/app/lib/a/private/key.pem", "key-bytes"),
				treeFile("opt/app/other/x.txt", "x-bytes"),
			},
			target: []treeEntry{treeFile("dest/lib/a/private/key.pem", "key-bytes")},
			matches: originalMatches{
				"/opt/app/lib/a/pub.so":          {{Source: "src", Path: "lib/a/pub.so"}},
				"/opt/app/lib/a/private/key.pem": {{Source: "src", Path: "lib/a/private/key.pem"}},
				"/opt/app/other/x.txt":           {{Source: "src", Path: "other/x.txt"}},
			},
			scope: ImportScope{
				Backend:      ImportBackendRsync,
				FromPath:     "/opt/app",
				ToPath:       "/dest",
				IncludePaths: []string{"lib"},
				ExcludePaths: []string{"**/private"},
			},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/lib/a/pub.so": {{Source: "src", Path: "lib/a/pub.so"}},
		}))
	})

	ginkgo.It("carries a whole directory import with no globs", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source: []treeEntry{
				treeFile("opt/app/bin/tool", "tool-bytes"),
				treeFile("opt/app/share/data.txt", "data-bytes"),
			},
			matches: originalMatches{
				"/opt/app/bin/tool":       {{Source: "src", Path: "bin/tool"}},
				"/opt/app/share/data.txt": {{Source: "src", Path: "share/data.txt"}},
			},
			scope: ImportScope{Backend: ImportBackendRsync, FromPath: "/opt/app", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/bin/tool":       {{Source: "src", Path: "bin/tool"}},
			"/dest/share/data.txt": {{Source: "src", Path: "share/data.txt"}},
		}))
	})

	ginkgo.It("carries a single file import under an existing destination directory", func(ctx ginkgo.SpecContext) {
		imported := importedOK(ctx, importCase{
			source:  []treeEntry{treeFile("opt/tool", "tool-bytes")},
			target:  []treeEntry{treeDir("dest")},
			matches: originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}},
			scope:   ImportScope{Backend: ImportBackendRsync, FromPath: "/opt/tool", ToPath: "/dest"},
		})

		gomega.Expect(imported).To(gomega.Equal(originalMatches{
			"/dest/tool": {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})
})

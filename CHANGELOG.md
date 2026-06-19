# Changelog

## [2.72.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.72.2-dk...v2.72.1-dk) (2026-06-19)


### Features

* add TypeScript chart rendering support (`NELM_FEAT_TYPESCRIPT=true`) ([#7341](https://github.com/deckhouse/delivery-kit/issues/7341)) ([b336225](https://github.com/deckhouse/delivery-kit/commit/b3362251a4786d78f7c2af17554ab5c7f4b1d503))
* **build-report:** support reading .env format build reports ([8e1501c](https://github.com/deckhouse/delivery-kit/commit/8e1501ce5ad068e9824dd3f3bc50c9e0bb94d3ad))
* **build, stapel, git:** add WERF_DISABLE_GIT_COMMIT_ANCESTRY_CHECK to disable git commit ancestry check ([bae3300](https://github.com/deckhouse/delivery-kit/commit/bae3300acc5d212f78f2d8f706c0aa4036e616f5))
* **build:** add commit to build report for images and stages ([#7566](https://github.com/deckhouse/delivery-kit/issues/7566)) ([38be712](https://github.com/deckhouse/delivery-kit/commit/38be712c95347a247e0ed022f4b624df0bfd3857))
* **build:** add image manifest & ELF signing, and dm-verity annotations ([55172eb](https://github.com/deckhouse/delivery-kit/commit/55172eb98059df20ab67fba26537a3237a83d4ca))
* **build:** add network isolation for Docker backend ([142ce04](https://github.com/deckhouse/delivery-kit/commit/142ce044ae5302bde6560e79fd33fd96ce3857f2))
* **build:** add network isolation for Docker backend ([6f41567](https://github.com/deckhouse/delivery-kit/commit/6f41567bbbc65776472e0a68f2a749a4324b38b3))
* **build:** add SBOM support during build with `werf sbom get` command ([acd0cbf](https://github.com/deckhouse/delivery-kit/commit/acd0cbf6cc217ae67d13068a847499bb44d76b59))
* **build:** document network isolation for build containers ([beb904f](https://github.com/deckhouse/delivery-kit/commit/beb904ff4699642809d9db9c8e58b772d29acc55))
* **build:** implement `werf stages copy` command to import/export stages (all or current build only) ([#7209](https://github.com/deckhouse/delivery-kit/issues/7209)) ([937b96a](https://github.com/deckhouse/delivery-kit/commit/937b96a9183e3356e98dab15c7e0f1a400e7b989))
* **build:** remove unused empty string argument in full dockerfile test ([09b3e43](https://github.com/deckhouse/delivery-kit/commit/09b3e4388bef76afb38eda38e9ebd6968ad0fc20))
* **build:** respect insecure registries and mirrors from backend-native config ([#7376](https://github.com/deckhouse/delivery-kit/issues/7376)) ([fd5a826](https://github.com/deckhouse/delivery-kit/commit/fd5a826680ecc2a5c0199462c856df4bec1f7ebd))
* **build:** scratch stapel docker backend ([#7441](https://github.com/deckhouse/delivery-kit/issues/7441)) ([490d6e0](https://github.com/deckhouse/delivery-kit/commit/490d6e0df8d0c559afb30736e09b6ef5bfb811c9))
* **build:** skip meta tags publication for read only registry ([#7291](https://github.com/deckhouse/delivery-kit/issues/7291)) ([7a80bbf](https://github.com/deckhouse/delivery-kit/commit/7a80bbfa6376e866d345ac5c74555419ac8bb76c))
* **build:** support network directive in werf.yaml ([30f8e0e](https://github.com/deckhouse/delivery-kit/commit/30f8e0e04ae4381ce213ba917d84dd112daa4897))
* **build:** support network directive in werf.yaml ([bf8482f](https://github.com/deckhouse/delivery-kit/commit/bf8482f6a72785fda0ff2e644c8c5d8d11d0e34c))
* **build:** use build report in commands require build ([#7297](https://github.com/deckhouse/delivery-kit/issues/7297)) ([d705476](https://github.com/deckhouse/delivery-kit/commit/d7054768e6ad297bb84d5cbd862031d5d496d26c))
* **ci-env:** add --use-docker-auth-config flag to generate Docker config from DOCKER_AUTH_CONFIG env var ([c2701f7](https://github.com/deckhouse/delivery-kit/commit/c2701f7f72ef177ca3edbff14cc64438a5cb025d))
* **cleanup:** add --kube-scan-namespaces support for in-cluster scan ([#7517](https://github.com/deckhouse/delivery-kit/issues/7517)) ([8941a1e](https://github.com/deckhouse/delivery-kit/commit/8941a1ed470be4265df080e3b87afb61288789b3))
* **cleanup:** delete rejected stages and linked custom tags during cleanup/purge ([#7576](https://github.com/deckhouse/delivery-kit/issues/7576)) ([b1b0980](https://github.com/deckhouse/delivery-kit/commit/b1b09809435789ad97dbce60c5a8be2886f0335a))
* **cleanup:** support kube token and kube token path ([#7327](https://github.com/deckhouse/delivery-kit/issues/7327)) ([352b8c3](https://github.com/deckhouse/delivery-kit/commit/352b8c349d7ee47cc27387ab8ca1e8f94f66c8b8))
* **config:** add packages directive to stapel image configuration ([9e40b37](https://github.com/deckhouse/delivery-kit/commit/9e40b372aaf2e42b9ec46d7ea310ddb035554e54))
* **deploy:** `--set-root-json` flag ([#7348](https://github.com/deckhouse/delivery-kit/issues/7348)) ([429ea3b](https://github.com/deckhouse/delivery-kit/commit/429ea3b4e221171f25fbc5954740af950d63cba5))
* **deploy:** `NELM_FEAT_MORE_DETAILED_EXIT_CODE_FOR_PLAN=true` to return exit code 3 on "no resource changes, but must install release" if `--exit-code` ([7dede71](https://github.com/deckhouse/delivery-kit/commit/7dede71bd2cca3043f5466de7c707df6b55ae222))
* **deploy:** `werf.io/delete-dependency-<id>` annotation ([#7337](https://github.com/deckhouse/delivery-kit/issues/7337)) ([05dfc1d](https://github.com/deckhouse/delivery-kit/commit/05dfc1d6aa38f3287256359dd1782a82cfcb1ea2))
* **deploy:** `werf.io/log-regex-skip` and `werf.io/log-regex-skip-for-<container>` annotations ([293c151](https://github.com/deckhouse/delivery-kit/commit/293c151f3fc4d99ad7617896a5ae79b45cd1291a))
* **deploy:** ability to init ts files with WerfRenderContext type ([#7464](https://github.com/deckhouse/delivery-kit/issues/7464)) ([1609845](https://github.com/deckhouse/delivery-kit/commit/160984521d67a403f34ec161afce8381fe9e422f))
* **deploy:** add plan freezing support ([#7362](https://github.com/deckhouse/delivery-kit/issues/7362)) ([28c053f](https://github.com/deckhouse/delivery-kit/commit/28c053faf35226d44ad530ec93000878e56e9640))
* **deploy:** add resource validation flags ([#7343](https://github.com/deckhouse/delivery-kit/issues/7343)) ([223d537](https://github.com/deckhouse/delivery-kit/commit/223d5373a9331704776939ca6b7e147a4179e13e))
* **deploy:** add structured image values to $.Values.global.werf.images ([#7413](https://github.com/deckhouse/delivery-kit/issues/7413)) ([1b93dcc](https://github.com/deckhouse/delivery-kit/commit/1b93dccbc7ae65877d316a16639ccd657ad9558e))
* **deploy:** adopt `chart ts init` for werf ([#7489](https://github.com/deckhouse/delivery-kit/issues/7489)) ([63542e2](https://github.com/deckhouse/delivery-kit/commit/63542e2ef392885b8d706ae8e42061fda71bd086))
* **deploy:** auto delete dependency detection ([#7342](https://github.com/deckhouse/delivery-kit/issues/7342)) ([ddb2087](https://github.com/deckhouse/delivery-kit/commit/ddb2087dc223a891129cc1de02db9f82608fd6ca))
* **deploy:** deno runtime for typescript ([#7365](https://github.com/deckhouse/delivery-kit/issues/7365)) ([c27c4d2](https://github.com/deckhouse/delivery-kit/commit/c27c4d29d2b4c46cf34b6ab33d37b1eeb81133ce))
* **deploy:** enhanced local resource validation ([#7335](https://github.com/deckhouse/delivery-kit/issues/7335)) ([bf1ef99](https://github.com/deckhouse/delivery-kit/commit/bf1ef99908f6d8eec8395d1560f3d27d21c4b045))
* **deploy:** implement resource validation against api spec ([#7328](https://github.com/deckhouse/delivery-kit/issues/7328)) ([b927515](https://github.com/deckhouse/delivery-kit/commit/b9275150606790bd7b16bef384baf8f97918278f))
* **deploy:** move `dockerconfigjson` to .global.werf ([#7583](https://github.com/deckhouse/delivery-kit/issues/7583)) ([79d90cb](https://github.com/deckhouse/delivery-kit/commit/79d90cb69f563a2ec7b109de5481c4eba45f9722))
* **deploy:** switch to goccy/go-yaml and improve parse error context ([#7398](https://github.com/deckhouse/delivery-kit/issues/7398)) ([3097703](https://github.com/deckhouse/delivery-kit/commit/3097703331ede996f9ea04ac0696372f9522ca8a))
* **host-cleanup:** add support for absolute storage units ([c5dbdd0](https://github.com/deckhouse/delivery-kit/commit/c5dbdd0cc422765d649a9dc053d78e2610a052cc))
* **host-cleanup:** make validation error more informative ([0f9f460](https://github.com/deckhouse/delivery-kit/commit/0f9f4605725b525dd9043c31406c95ee56680318))
* **host-cleanup:** move units package to pkg/host_cleaning ([6f3d931](https://github.com/deckhouse/delivery-kit/commit/6f3d93135de8a7900d3f2b6890e5c5ecdb58c820))
* **host-clenaup:** cli docs generated ([248fdb6](https://github.com/deckhouse/delivery-kit/commit/248fdb66dc554b2f809bcad5e0d963ac7c8a8807))
* **import:** provide WERF_EXPERIMENTAL_IMPORT_BY_SOURCE_IMAGE_TAG env to change calculation import checksums method to reduce FD  ([#7392](https://github.com/deckhouse/delivery-kit/issues/7392)) ([9abe1b5](https://github.com/deckhouse/delivery-kit/commit/9abe1b5c09773917a764b1e89e12a37af217edf0))
* **sbom:** add --tag and --digest flags to `get` command ([#76](https://github.com/deckhouse/delivery-kit/issues/76)) ([aeb693f](https://github.com/deckhouse/delivery-kit/commit/aeb693fa9b5851c662fbd5978305f6d6c6072861))
* **sbom:** add declarations merge ([e0b79a7](https://github.com/deckhouse/delivery-kit/commit/e0b79a76b24931cfecc0a559634fad9276a827bc))
* **sbom:** add dependencies merge ([e97470c](https://github.com/deckhouse/delivery-kit/commit/e97470cc154ed0ad7c9c3f68317e1083cbfb7c6b))
* **sbom:** add experimental GOST SBOM support ([#48](https://github.com/deckhouse/delivery-kit/issues/48)) ([3711453](https://github.com/deckhouse/delivery-kit/commit/37114536887ac981e9cb876251f43dc41e5f4b79))
* **sbom:** add external references enrichment ([#98](https://github.com/deckhouse/delivery-kit/issues/98)) ([2fb36a3](https://github.com/deckhouse/delivery-kit/commit/2fb36a38520331825de337d46c40bcfc57d73cc8))
* **sbom:** add log warning for SBOM emulation mode ([b186e3c](https://github.com/deckhouse/delivery-kit/commit/b186e3c21b72b983cb31c24f48415aadcb188a76))
* **sbom:** add sbom merge command ([e73f614](https://github.com/deckhouse/delivery-kit/commit/e73f61422b39fde37988d4e9f2c571a6ea06103b))
* **sbom:** adopt OCI artifact-based registry-only storage ([574e35b](https://github.com/deckhouse/delivery-kit/commit/574e35be82ca28949885165a0fc51e3310d83c86))
* **sbom:** disable current validation for base/import images SBOM ([#78](https://github.com/deckhouse/delivery-kit/issues/78)) ([eda9fc2](https://github.com/deckhouse/delivery-kit/commit/eda9fc26e3c6477b6c20ca1bb3cb87faa24749a3))
* **sbom:** implement ispras validating ([1f9ccb0](https://github.com/deckhouse/delivery-kit/commit/1f9ccb0cc420d1683426a4843d46e4b56045bef5))
* **sbom:** resolve version unknown ([#58](https://github.com/deckhouse/delivery-kit/issues/58)) ([5956afc](https://github.com/deckhouse/delivery-kit/commit/5956afc805d1e13bd1a3d7c56855ceaa155a7228))
* **sbom:** sbom fstec mvp ([#29](https://github.com/deckhouse/delivery-kit/issues/29)) ([850518c](https://github.com/deckhouse/delivery-kit/commit/850518c4b0f82056894af40628e086391499a708))
* **sbom:** skip SBOM generation for trusted builder images ([#103](https://github.com/deckhouse/delivery-kit/issues/103)) ([f796445](https://github.com/deckhouse/delivery-kit/commit/f796445cde4d910df4a9557a4b09c4740ff034e6))
* **sign:** add werf verify command ([8f40f5a](https://github.com/deckhouse/delivery-kit/commit/8f40f5a7c7e282d6c85ff75eaaa73d068772d703))
* **stapel:** provide WERF_EXPERIMENTAL_STAPEL_ARM env for arm64 support ([#7454](https://github.com/deckhouse/delivery-kit/issues/7454)) ([f911913](https://github.com/deckhouse/delivery-kit/commit/f911913c70d523039a9dc808781b2a3a509158b3))
* **telemetry:** extend build metrics with metadata fields ([#7384](https://github.com/deckhouse/delivery-kit/issues/7384)) ([09a324e](https://github.com/deckhouse/delivery-kit/commit/09a324e383e26367d3b6e2a5190ca181c397b49a))


### Bug Fixes

* --set-root-json not working ([#7374](https://github.com/deckhouse/delivery-kit/issues/7374)) ([613f2e1](https://github.com/deckhouse/delivery-kit/commit/613f2e1c987d56e1281a4e75dec18c70a81712af))
* **buiild, stapel, import:** regenerate import checksums if it`s empty ([#7506](https://github.com/deckhouse/delivery-kit/issues/7506)) ([eebb1df](https://github.com/deckhouse/delivery-kit/commit/eebb1dfdd0ceab4ef7f274a89d122a44942fdffb))
* **build, buildah:** apply owner group to dst dir ([#7462](https://github.com/deckhouse/delivery-kit/issues/7462)) ([fea6b40](https://github.com/deckhouse/delivery-kit/commit/fea6b40124316be1d5742d06b81ff338c4d4be30))
* **build, buildah:** correct expansion of instructions ([#7460](https://github.com/deckhouse/delivery-kit/issues/7460)) ([aef6003](https://github.com/deckhouse/delivery-kit/commit/aef600313e0642a1e4c070f826b28008050c10e6))
* **build, buildah:** fix multiarch build failing with "image not known" for cross-platform images ([#7573](https://github.com/deckhouse/delivery-kit/issues/7573)) ([8cd109f](https://github.com/deckhouse/delivery-kit/commit/8cd109fa79cf5e951d409279fad2306f707ca5bb))
* **build, docker, dockerfile:** don't post cleanup images ([#7313](https://github.com/deckhouse/delivery-kit/issues/7313)) ([f7bf030](https://github.com/deckhouse/delivery-kit/commit/f7bf0305cc1c19632ef20250330fb479ed09c9a9))
* **build, docker, stapel:** fix stage image cache for multi-platform builds ([#7480](https://github.com/deckhouse/delivery-kit/issues/7480)) ([23f89b3](https://github.com/deckhouse/delivery-kit/commit/23f89b3a7f9ee9d4c2aebeeb26d1e334990ef859))
* **build, dockerfile, staged:** fix staged dockerfile dependencies for COPY --from ([#7300](https://github.com/deckhouse/delivery-kit/issues/7300)) ([18e3c64](https://github.com/deckhouse/delivery-kit/commit/18e3c6498f9ed6ab1acfd291bd235d5dc1e76d2f))
* **build, docker:** handle `no such container` error ([#7482](https://github.com/deckhouse/delivery-kit/issues/7482)) ([83b3227](https://github.com/deckhouse/delivery-kit/commit/83b32279e9f6893cc6f06e7d812944c7231636dc))
* **build, docker:** robust image ID extraction for buildx across different Docker storage drivers ([#7345](https://github.com/deckhouse/delivery-kit/issues/7345)) ([db3c046](https://github.com/deckhouse/delivery-kit/commit/db3c046ecf18f2ff2d52d09f07a206f006e2b909))
* **build, import:** avoid following symlinks during checksum calculation to prevent runner stalls ([9ee46f2](https://github.com/deckhouse/delivery-kit/commit/9ee46f239c55f983e37beacf0419e979f08bae12))
* **build, import:** should not resolve symlinks ([c28127a](https://github.com/deckhouse/delivery-kit/commit/c28127a095e6153ca8d295cb0165d96441ff3e24))
* **build, stapel, buildah:** binary files patch incorrect ([#7310](https://github.com/deckhouse/delivery-kit/issues/7310)) ([2eec873](https://github.com/deckhouse/delivery-kit/commit/2eec873ef6a880baab16b5c59c20afbadafcf29f))
* **build, stapel, import, buildah:** close file descriptors in checksum calculation loop ([#7320](https://github.com/deckhouse/delivery-kit/issues/7320)) ([b4f5124](https://github.com/deckhouse/delivery-kit/commit/b4f51241d82fa8ada6e5bb1fbad0ef53729faa59))
* **build, stapel, import:** importing into symlinked directories no longer silently loses files ([#7545](https://github.com/deckhouse/delivery-kit/issues/7545)) ([9d1bb68](https://github.com/deckhouse/delivery-kit/commit/9d1bb68caae3f55f4b4d3de419eb44653661b47a))
* **build, stapel, import:** orphan import-server containers after cancellation ([#7527](https://github.com/deckhouse/delivery-kit/issues/7527)) ([5c75bea](https://github.com/deckhouse/delivery-kit/commit/5c75bea7aafb664c912e052105bc007a0f522a7e))
* **build, stapel, import:** rsync chown "/sys" Read-only file system on to: / ([#7590](https://github.com/deckhouse/delivery-kit/issues/7590)) ([b6dac9c](https://github.com/deckhouse/delivery-kit/commit/b6dac9c9835e5a9d3745f865ee5ab3944828f6c4))
* **build, stapel, import:** unnecessary image rebuilds when using --secondary-repo with imports ([#7526](https://github.com/deckhouse/delivery-kit/issues/7526)) ([915a403](https://github.com/deckhouse/delivery-kit/commit/915a403a4ec8cf4e5835bf3caa277d7ddafdcb06))
* **build, stapel:** handle platform mismatch in stage base image resolution and avoid panic ([#7493](https://github.com/deckhouse/delivery-kit/issues/7493)) ([cdf0e83](https://github.com/deckhouse/delivery-kit/commit/cdf0e831b127cd041141aa9ecf951e12056e2135))
* **build:** add broken image error handling for image-spec stage ([#7322](https://github.com/deckhouse/delivery-kit/issues/7322)) ([56fb883](https://github.com/deckhouse/delivery-kit/commit/56fb88304d35c94aa812444ec3cfb1ed439b93b6))
* **build:** add custom-tag once ([2e23d3f](https://github.com/deckhouse/delivery-kit/commit/2e23d3fa19fb92b41e5ffc353c1f85014a53539a))
* **build:** add custom-tag once ([#7275](https://github.com/deckhouse/delivery-kit/issues/7275)) ([e4953e7](https://github.com/deckhouse/delivery-kit/commit/e4953e7f4cdc11b4613a59897834ba7bfb132416))
* **build:** add prune empty dirs to rsync server ([939942b](https://github.com/deckhouse/delivery-kit/commit/939942b620e7e0ad26e3f4fa292566d000224f6e))
* **buildah:** extract resolveContainerBackendType and reuse it in localPurger to skip stapel purge for non-Docker backends ([e10de67](https://github.com/deckhouse/delivery-kit/commit/e10de6729deb5f25568f58b1918e1cc19e106774))
* **buildah:** fix panic in "host purge" when running in buildah mode ([a3ae3df](https://github.com/deckhouse/delivery-kit/commit/a3ae3df9f46eee32dbfe16cc947a9a9f733e92ae))
* **buildah:** heredoc in the Dockerfile is not taken into account during the build with staged: true ([#7279](https://github.com/deckhouse/delivery-kit/issues/7279)) ([3c73afb](https://github.com/deckhouse/delivery-kit/commit/3c73afbc55bf83c751e6544c6e605943327e7609))
* **buildah:** normalize dependency import file targets ([69cf22f](https://github.com/deckhouse/delivery-kit/commit/69cf22f133de280b2bf6297e359ca69e067efa71))
* **build:** bound retry loop on unexpected stages storage state and invalidate manifest cache on stage rejection ([#7369](https://github.com/deckhouse/delivery-kit/issues/7369)) ([9e3c8a1](https://github.com/deckhouse/delivery-kit/commit/9e3c8a1ac474fd976c78c16a49e12d9f78497de0))
* **build:** eliminate redundant registry tag listing in post-build metadata publication ([#7559](https://github.com/deckhouse/delivery-kit/issues/7559)) ([27404cb](https://github.com/deckhouse/delivery-kit/commit/27404cbddca0e4d8f20680fc8bba4cc5cee8d436))
* **build:** fix git owner and group with buildah backend ([#7415](https://github.com/deckhouse/delivery-kit/issues/7415)) ([7af23b6](https://github.com/deckhouse/delivery-kit/commit/7af23b66ec6dd59850abcd80babae4134d34d65e))
* **build:** fix image-spec immutability ([#7288](https://github.com/deckhouse/delivery-kit/issues/7288)) ([69e7154](https://github.com/deckhouse/delivery-kit/commit/69e7154298b516c8fcca851b6969a5515e384563))
* **build:** fix stage build time in report ([#7404](https://github.com/deckhouse/delivery-kit/issues/7404)) ([74ae247](https://github.com/deckhouse/delivery-kit/commit/74ae2474c0610232c9bdacc377bf5b5d76d43f5f))
* **build:** freezing on random image ([#7539](https://github.com/deckhouse/delivery-kit/issues/7539)) ([6cf58b7](https://github.com/deckhouse/delivery-kit/commit/6cf58b7b35dcf30d3e8bc84a13118700faa37b58))
* **build:** handle broken import metadata images in container registry ([#7394](https://github.com/deckhouse/delivery-kit/issues/7394)) ([0413384](https://github.com/deckhouse/delivery-kit/commit/04133847bed3b8842ab1b45609a4f81d468c6af2))
* **build:** highlight an error in parallel mode ([a3f509a](https://github.com/deckhouse/delivery-kit/commit/a3f509ae680b13417b59dd128f66fb601f321dd6))
* **build:** impl requested changes ([9973a27](https://github.com/deckhouse/delivery-kit/commit/9973a2795439a400e102541049934f7470da2927))
* **build:** impl requested changes ([2811f4e](https://github.com/deckhouse/delivery-kit/commit/2811f4e6536b9dabcf192548869338487699389c))
* **build:** non-local synchronization server requires --repo be set ([f078e04](https://github.com/deckhouse/delivery-kit/commit/f078e049261c35e2a4fced88a92a078205021806))
* **build:** panic: image "..." not found ([#7318](https://github.com/deckhouse/delivery-kit/issues/7318)) ([145064e](https://github.com/deckhouse/delivery-kit/commit/145064e25ef9e4e567e0dd10805aad165680b3d5))
* **build:** push custom tags to final repo during multiplatform builds ([a402ac6](https://github.com/deckhouse/delivery-kit/commit/a402ac63d42ac92f7d9870ceca559bfce93fa937))
* **build:** refactor file path parse command, now symlinks considered without resolving ([3145852](https://github.com/deckhouse/delivery-kit/commit/31458529db824a05e42146aa8eac187082c95e1a))
* **build:** resolve dependency image refs in FROM stage before computing cache digest ([#7492](https://github.com/deckhouse/delivery-kit/issues/7492)) ([b42f0b1](https://github.com/deckhouse/delivery-kit/commit/b42f0b120a46e7eeaf06f66339561ed486cc04c9))
* **build:** sanitize docker credentials from buildkit and docker errors ([#7299](https://github.com/deckhouse/delivery-kit/issues/7299)) ([ae50410](https://github.com/deckhouse/delivery-kit/commit/ae504101c171bd75fe6666113256ff2d75c79548))
* **build:** show "default" in log network field when no explicit network ([c54a78d](https://github.com/deckhouse/delivery-kit/commit/c54a78da6c956455578d4c2a67064276498b0f68))
* **build:** test custom-tag case ([63168e7](https://github.com/deckhouse/delivery-kit/commit/63168e76d4a59bfcbb39dc57df88c05c7a2a90b7))
* **build:** test custom-tag once ([699fd4d](https://github.com/deckhouse/delivery-kit/commit/699fd4d70389e028d90ccf080cc1bdda5176f1e8))
* **build:** use image tag instead of sha256 for docker run ([725a629](https://github.com/deckhouse/delivery-kit/commit/725a62942d4fe57f8d88093d636d5f7be750ab5d))
* **build:** use path.Join for container-internal paths in stapel ([#7258](https://github.com/deckhouse/delivery-kit/issues/7258)) ([c974594](https://github.com/deckhouse/delivery-kit/commit/c974594d3c4d7ade4fe2fe9865bd6dec5c1bd6e4))
* **build:** use registry-mirrors from docker daemon.json ([#7329](https://github.com/deckhouse/delivery-kit/issues/7329)) ([0fdeb86](https://github.com/deckhouse/delivery-kit/commit/0fdeb8696b321b8ba19e18cf3ace246e288eb9bd))
* **ci-env:** ci-env ignores session docker config when WERF_DOCKER_CONFIG is set ([#7530](https://github.com/deckhouse/delivery-kit/issues/7530)) ([5161412](https://github.com/deckhouse/delivery-kit/commit/5161412b021bce794dd8a87bb51113854152acb7))
* **ci-env:** optimize docker config copying to prevent inodes overflow ([#7305](https://github.com/deckhouse/delivery-kit/issues/7305)) ([d5005c1](https://github.com/deckhouse/delivery-kit/commit/d5005c15301f90341fa8139213e4ad3311c87287))
* **ci:** comment out cr in daily tests ([#13](https://github.com/deckhouse/delivery-kit/issues/13)) ([34708ff](https://github.com/deckhouse/delivery-kit/commit/34708ffaa7372b21d764e1a76d222b031891c7c7))
* **ci:** fix publish binary name ([0cea40c](https://github.com/deckhouse/delivery-kit/commit/0cea40cfc3befc866a12954ed40606c1cb68b7ec))
* **ci:** pr docs preview ([#7485](https://github.com/deckhouse/delivery-kit/issues/7485)) ([d29c18b](https://github.com/deckhouse/delivery-kit/commit/d29c18b1fb868c0eaab8a2eacfd0a1223b1b1eca))
* **ci:** skip buildah tests for main ([#11](https://github.com/deckhouse/delivery-kit/issues/11)) ([6c52c77](https://github.com/deckhouse/delivery-kit/commit/6c52c77d96eda2bbc1283aabd457d6c2ad3cf4a8))
* **ci:** stabilize integration tests and multi-arch build ([#17](https://github.com/deckhouse/delivery-kit/issues/17)) ([0bb96f2](https://github.com/deckhouse/delivery-kit/commit/0bb96f2d7e5ecb81b132d1d3b725b89ff6d92be5))
* **ci:** switch release-please to manifest mode, fix upstream werf baseline contamination ([#124](https://github.com/deckhouse/delivery-kit/issues/124)) ([f00cd16](https://github.com/deckhouse/delivery-kit/commit/f00cd165b9189bee3e26b4f60121888c307b7f7d))
* **ci:** trigger website production deploy after trdl channel update ([#7502](https://github.com/deckhouse/delivery-kit/issues/7502)) ([310298c](https://github.com/deckhouse/delivery-kit/commit/310298c5ba2f7f1e88c49bd8c45c2eedb4986c2d))
* **cleanup:** do not require docker daemon for registry mirrors ([7a42d33](https://github.com/deckhouse/delivery-kit/commit/7a42d33ee17eb35a807580c1d7ae39aab4e56cef))
* **cleanup:** ensure tag is deleted before manifest removal ([#7401](https://github.com/deckhouse/delivery-kit/issues/7401)) ([303506e](https://github.com/deckhouse/delivery-kit/commit/303506ede573f252d87c2d7b0f14a1b149ffdd59))
* **cleanup:** failing for cross-account ECR repositories ([37c636c](https://github.com/deckhouse/delivery-kit/commit/37c636cb252d765a4c83d901f05b7abd9bf56175))
* **cleanup:** normalize 404 error message on tag deletion ([#7332](https://github.com/deckhouse/delivery-kit/issues/7332)) ([72deb33](https://github.com/deckhouse/delivery-kit/commit/72deb338e33f5222c686b4eaa828ba0568481f3f))
* **cleanup:** skip invalid custom tag metadata with warning log ([65ff126](https://github.com/deckhouse/delivery-kit/commit/65ff12612bf9487fe1e49f4064f3354a059a3b15))
* **compose:** show docker compose config error instead of bare exit code ([6cc27d8](https://github.com/deckhouse/delivery-kit/commit/6cc27d81cad9266b37053ac35c9f73612ec0d904))
* **config:** align .Files.Glob behavior with helm ([7959568](https://github.com/deckhouse/delivery-kit/commit/7959568a2d69e6774f6323fef54adee43665c181))
* **deploy:** add standalone pod tracking ([#7316](https://github.com/deckhouse/delivery-kit/issues/7316)) ([418e21a](https://github.com/deckhouse/delivery-kit/commit/418e21a078e3d3df19211f8b4427b9764babc7af))
* **deploy:** adjust service account managed fields ([#7319](https://github.com/deckhouse/delivery-kit/issues/7319)) ([751a900](https://github.com/deckhouse/delivery-kit/commit/751a900449680f6101496471df395d124798f46e))
* **deploy:** adopt managed fields after migration from helm to nelm ([#7406](https://github.com/deckhouse/delivery-kit/issues/7406)) ([ac46e88](https://github.com/deckhouse/delivery-kit/commit/ac46e88d933b80618aa16155ac926ae171852f8c))
* **deploy:** adopt managed fields after migration from helm to nelm ([#7406](https://github.com/deckhouse/delivery-kit/issues/7406)) ([eab87e5](https://github.com/deckhouse/delivery-kit/commit/eab87e518f81ea86384f081bb509bae3b00a3104))
* **deploy:** autodependencies between pods/controllers, rolebindings and serviceaccounts ([#7567](https://github.com/deckhouse/delivery-kit/issues/7567)) ([f152352](https://github.com/deckhouse/delivery-kit/commit/f1523529a7ff3e7e40515dcd1c3e06c10dac13bd))
* **deploy:** docker hub creds might leak in pod events ([62adcb4](https://github.com/deckhouse/delivery-kit/commit/62adcb482c07749ea83840e41698dd36622da2c8))
* **deploy:** force adoption always on ([8154022](https://github.com/deckhouse/delivery-kit/commit/81540220e26c0080971f70b60e68d26c0504d953))
* **deploy:** goroutine leak in watch error channel consumer for ReleaseInstall, ReleaseUninstall and ReleaseRollback ([#7418](https://github.com/deckhouse/delivery-kit/issues/7418)) ([f2d817c](https://github.com/deckhouse/delivery-kit/commit/f2d817cbef24017ad7073d1e949c16d1873917bd))
* **deploy:** hangs on very long pod lines ([#7580](https://github.com/deckhouse/delivery-kit/issues/7580)) ([daefa02](https://github.com/deckhouse/delivery-kit/commit/daefa02fb7bb1e6146f7f2e6f78db6e7738375ee))
* **deploy:** hooks cleaned up too early ([42c57b4](https://github.com/deckhouse/delivery-kit/commit/42c57b4e077d7b0b02f64f0b194155856248a2af))
* **deploy:** logs stop showing after 4 hours ([e33523b](https://github.com/deckhouse/delivery-kit/commit/e33523bf4a05ab89e92cd66780fe9382f5335e95))
* **deploy:** no more "no match for resource kind" errors ([#7585](https://github.com/deckhouse/delivery-kit/issues/7585)) ([a3d0a5a](https://github.com/deckhouse/delivery-kit/commit/a3d0a5ae7b5110edd6c9ae63b64135b264c6ea31))
* **deploy:** panic if apiserver connection lost ([7358731](https://github.com/deckhouse/delivery-kit/commit/7358731ac6f53f2e3532c1cbd9eae2c257ff7a06))
* **deploy:** panic in pre/post-delete hooks tracking ([839074f](https://github.com/deckhouse/delivery-kit/commit/839074fd0b80cf957c24ae3e57ff923b46623d24))
* **deploy:** pass option for yaml validator to allow duplicate map key ([#7408](https://github.com/deckhouse/delivery-kit/issues/7408)) ([ac46e88](https://github.com/deckhouse/delivery-kit/commit/ac46e88d933b80618aa16155ac926ae171852f8c))
* **deploy:** pass option for yaml validator to allow duplicate map key ([#7408](https://github.com/deckhouse/delivery-kit/issues/7408)) ([c9ea743](https://github.com/deckhouse/delivery-kit/commit/c9ea743659a900b65c12ebcacc30ddf1b6147a99))
* **deploy:** print engine.Render() result on debug level ([#7396](https://github.com/deckhouse/delivery-kit/issues/7396)) ([7237218](https://github.com/deckhouse/delivery-kit/commit/7237218b844f3487048234bedf450c26b01a542d))
* **deploy:** release had pending status after error instead of failed ([#7416](https://github.com/deckhouse/delivery-kit/issues/7416)) ([b523cf2](https://github.com/deckhouse/delivery-kit/commit/b523cf2cc1f71b0f78b9cb165e584254ce267682))
* **deploy:** restore `global.env` ([5e5defd](https://github.com/deckhouse/delivery-kit/commit/5e5defd1833a969a1a6073f7d4bdf5362d31d5f8))
* **deploy:** restore WERF_EXPERIMENT_NO_GLOBAL_SERVICE_VALUES env ([#7468](https://github.com/deckhouse/delivery-kit/issues/7468)) ([e2e0999](https://github.com/deckhouse/delivery-kit/commit/e2e0999a5e49094c76c81fb35625d145810892cf))
* **deploy:** retry also on conversion webhooks unavailability ([#7587](https://github.com/deckhouse/delivery-kit/issues/7587)) ([1623efe](https://github.com/deckhouse/delivery-kit/commit/1623efe0fa246d3b6917786e7033d882101e1391))
* **deploy:** retry on "webhook unavailable" error ([#7533](https://github.com/deckhouse/delivery-kit/issues/7533)) ([8810e23](https://github.com/deckhouse/delivery-kit/commit/8810e23e8ed4545a3d532d2df69e3c1b28e56866))
* **deploy:** retry on webhook unavailable errors ([#7505](https://github.com/deckhouse/delivery-kit/issues/7505)) ([1718543](https://github.com/deckhouse/delivery-kit/commit/171854373681fc3c98b1c381052281b026e71c12))
* **deploy:** show actual error if webhook retries fail ([#7586](https://github.com/deckhouse/delivery-kit/issues/7586)) ([1dc615e](https://github.com/deckhouse/delivery-kit/commit/1dc615ecc97e1fd25d4ad8f96b2850082bf8a022))
* **deploy:** tracking absence for release namespace deletion ([#7397](https://github.com/deckhouse/delivery-kit/issues/7397)) ([6d885d9](https://github.com/deckhouse/delivery-kit/commit/6d885d92b71ec190ab989c1b6a07e1a997a4cfc0))
* **host-cleanup:** fix absolute volume usage unit parsing logic ([0e3f5d6](https://github.com/deckhouse/delivery-kit/commit/0e3f5d6b513e0091f3f4c68bd7bbbf4802554627))
* **host-cleanup:** handle race condition in tmp files GC when entries disappear between readdir and stat ([18ff151](https://github.com/deckhouse/delivery-kit/commit/18ff151563b7b22e6062fff5132943102ebb7ee3))
* **host-cleanup:** support nested cli command ([ee5f78a](https://github.com/deckhouse/delivery-kit/commit/ee5f78a7b05cebc3b1334d0e885c1b1aa8aaffdd))
* **host-clenaup:** apply WERF_SELF_INVOCATION_COMMAND in Detach ([faf5bf2](https://github.com/deckhouse/delivery-kit/commit/faf5bf2c6552b38cfe8881d334a862d636d08612))
* **host-clenaup:** prevent overflow while subtraction (math) ([544c423](https://github.com/deckhouse/delivery-kit/commit/544c423573985acba5150476774f1d4a64e311af))
* **import:** add check to handle symlinks before md5sum launch ([679bc6a](https://github.com/deckhouse/delivery-kit/commit/679bc6a104c605c1f8a8284349d58ed8d5f530a2))
* **import:** add one fs rsync flag ([c64e3e7](https://github.com/deckhouse/delivery-kit/commit/c64e3e72eb81a507821e6865f6af5ed0631d7a3a))
* **includes, giterminism:** fix includePaths handling ([#7321](https://github.com/deckhouse/delivery-kit/issues/7321)) ([b71c543](https://github.com/deckhouse/delivery-kit/commit/b71c54352c73afd151196d62c9916b3503d053d1))
* **includes:** add empty args check ([a6b8766](https://github.com/deckhouse/delivery-kit/commit/a6b87668af0fa7fb7478fa6b502c6c98dd62eb11))
* **includes:** create local branch refs after fresh clone in CloneAndFetch ([#7425](https://github.com/deckhouse/delivery-kit/issues/7425)) ([4c94b0b](https://github.com/deckhouse/delivery-kit/commit/4c94b0badd4d1a7daa19542acad79b631e0f0038))
* **includes:** respect --loose-giterminism for --allow-includes-update ([#7414](https://github.com/deckhouse/delivery-kit/issues/7414)) ([db75a5a](https://github.com/deckhouse/delivery-kit/commit/db75a5a7fcf2c1abe0eba8033831f1c672bb169f))
* init docker config in InitCommonComponents when docker registry is requested ([#7488](https://github.com/deckhouse/delivery-kit/issues/7488)) ([76ca703](https://github.com/deckhouse/delivery-kit/commit/76ca703c53611a0a9612e8f5fff98ced20fb4b67))
* **kube:** correctly resolve client config per context ([5f12fed](https://github.com/deckhouse/delivery-kit/commit/5f12fed8555a59c6f66d555848a0aaf1da7f4e78))
* make kube initialization lazy for commands that don't need eager kube client ([#7440](https://github.com/deckhouse/delivery-kit/issues/7440)) ([98028f2](https://github.com/deckhouse/delivery-kit/commit/98028f28ce629da894a8bad00a5cbe96ca2bceb7))
* **parallel:** eliminate race between context timeout and goroutine ([ed67c0f](https://github.com/deckhouse/delivery-kit/commit/ed67c0f7f988a3bcf489baad9d428850fa6d3326))
* propagate --docker-config to image pulling in bundle copy ([#7448](https://github.com/deckhouse/delivery-kit/issues/7448)) ([c02babe](https://github.com/deckhouse/delivery-kit/commit/c02babecf9b7e768edf18ca71b6eaabd7a87c37f))
* regenerate mock for LegacyContainerOptions to add missing AddNetwork method ([1ea6c3a](https://github.com/deckhouse/delivery-kit/commit/1ea6c3a72eee71c66ee8aea82eff9dd6c790d55e))
* regenerate mocks and add missing Mutate method to test stub ([0cbb7b5](https://github.com/deckhouse/delivery-kit/commit/0cbb7b50ade11ad6aeabf75a0fdbfdc7e9ec7218))
* **sbom, docker:** tar sbom artifact correctly ([1cbe5a9](https://github.com/deckhouse/delivery-kit/commit/1cbe5a90f787e365c5d963684dcaa57682b743cf))
* **sbom:** add cross-project merge support ([#37](https://github.com/deckhouse/delivery-kit/issues/37)) ([62a11b5](https://github.com/deckhouse/delivery-kit/commit/62a11b50a8356065f8c335206ee4766cd4b8983b))
* **sbom:** enable offline validation of CycloneDX 1.6 external schemas ([6438078](https://github.com/deckhouse/delivery-kit/commit/6438078487072ddd6af4cc1c0d3106442146ceb1))
* **sbom:** ensure bom-ref uniqueness in cyclonedx@1.6 SBOM merge ([#71](https://github.com/deckhouse/delivery-kit/issues/71)) ([f5e1471](https://github.com/deckhouse/delivery-kit/commit/f5e14713201ad15f53b5f2492bfbb07c6c66de14))
* **sbom:** implement mark and sweep model ([72c5418](https://github.com/deckhouse/delivery-kit/commit/72c5418f93a3837ba0c65453d95325693cb19948))
* **sbom:** init components deduplication ([57fe3a5](https://github.com/deckhouse/delivery-kit/commit/57fe3a5b4adf6b5787070043bc7eb1da9aa01781))
* **sbom:** migrate `inherit` value to `indirect` in gost fields ([672075c](https://github.com/deckhouse/delivery-kit/commit/672075c56fe06b84c93416e64965c3a248447283))
* **sbom:** relocate syft image from GitHub to Docker Hub ([65682ce](https://github.com/deckhouse/delivery-kit/commit/65682ce79eb009d804264b16e5186ddcdfb70a2e))
* **sbom:** take *-sbom images into account with cleanup commands ([3f53e88](https://github.com/deckhouse/delivery-kit/commit/3f53e88f7323664761dce5b2cacbdd8eeb7dadf9))
* **sbom:** throw warning instead of error when base/import image sbom is missing ([#56](https://github.com/deckhouse/delivery-kit/issues/56)) ([99fa295](https://github.com/deckhouse/delivery-kit/commit/99fa295d9509e95ceb2e606291b37e6bbe048f3c))
* **sbom:** use cache instead of generate SBOM ([dc38dde](https://github.com/deckhouse/delivery-kit/commit/dc38ddeb331c666c7b7b4b2226f8dd21d1ddd81d))
* **stages-copy:** fix panic ([#7382](https://github.com/deckhouse/delivery-kit/issues/7382)) ([08d91de](https://github.com/deckhouse/delivery-kit/commit/08d91defda828a06bf8cd96c3f420542c6716739))
* stop retrying 301 redirects in registry transport ([#7457](https://github.com/deckhouse/delivery-kit/issues/7457)) ([f588d4c](https://github.com/deckhouse/delivery-kit/commit/f588d4ca3ef8d74009e451e640b7d40f0b3938e6))


### Miscellaneous Chores

* **main:** release 2.62.1-dk ([a4d0a83](https://github.com/deckhouse/delivery-kit/commit/a4d0a8323375502c5f098ea8558e8a6ee37c673b))
* **main:** trigger release please ([ba1a3a7](https://github.com/deckhouse/delivery-kit/commit/ba1a3a7169a9a64d21f6e22858e1df28d47fdf30))
* release 2.68.0 ([9795718](https://github.com/deckhouse/delivery-kit/commit/979571877728d066d88ae121c968d5de212dc130))
* release 2.68.2 ([5fb7971](https://github.com/deckhouse/delivery-kit/commit/5fb7971724fa48c1dc441e5094e7bb4e61d3e420))
* release 2.70.0 ([a9aee60](https://github.com/deckhouse/delivery-kit/commit/a9aee60115cd0060de74acc7cdab9b19f413959b))
* release 2.70.1 ([5232348](https://github.com/deckhouse/delivery-kit/commit/5232348fb5177dd53d5ddef18c5b8c8d7b9a93b1))
* **release:** force 2.57.1 ([9400070](https://github.com/deckhouse/delivery-kit/commit/9400070341b58e9dce1025ac465cd3e6a6319e7c))
* **release:** force 2.61.1 ([615246c](https://github.com/deckhouse/delivery-kit/commit/615246c806cb250bf7c07fb894acf10ef225a6ba))
* **release:** force 2.62.2-dk ([0c05275](https://github.com/deckhouse/delivery-kit/commit/0c05275d32f26e1c52959c0a089a5c7096ff6f64))
* **release:** force 2.63.1-dk ([6795823](https://github.com/deckhouse/delivery-kit/commit/67958234823178d7cd9c07fe480f5e218bb674f9))
* **release:** force v2.55.2 ([c1f60fc](https://github.com/deckhouse/delivery-kit/commit/c1f60fc0e860368b65bcc9a114057da91e966076))
* **release:** force v2.55.3 ([4705747](https://github.com/deckhouse/delivery-kit/commit/47057475f3da1997e580946bc0f3535c69ab6173))
* **release:** force v2.69.0-dk ([dc8c080](https://github.com/deckhouse/delivery-kit/commit/dc8c080015b40f9d18c0277f0f8fca9b701f4ed4))
* **release:** force v2.72.0-dk ([8460fea](https://github.com/deckhouse/delivery-kit/commit/8460feaab224efc1d7eca287067dbba23eabd001))
* trigger release-please ([0609192](https://github.com/deckhouse/delivery-kit/commit/0609192f9f88097e62b46cca2729606a7c2f1a2e))

## [2.72.2-dk](https://github.com/deckhouse/delivery-kit/compare/v2.72.1-dk...v2.72.2-dk) (2026-06-19)


### Features

* **deploy:** move `dockerconfigjson` to .global.werf ([#7583](https://github.com/deckhouse/delivery-kit/issues/7583)) ([79d90cb](https://github.com/deckhouse/delivery-kit/commit/79d90cb69f563a2ec7b109de5481c4eba45f9722))


### Bug Fixes

* **build, stapel, import:** rsync chown "/sys" Read-only file system on to: / ([#7590](https://github.com/deckhouse/delivery-kit/issues/7590)) ([b6dac9c](https://github.com/deckhouse/delivery-kit/commit/b6dac9c9835e5a9d3745f865ee5ab3944828f6c4))

## [2.72.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.72.0-dk...v2.72.1-dk) (2026-06-18)


### Bug Fixes

* **build:** use tag cache for rejected stage check in GetStageDesc ([#7584](https://github.com/deckhouse/delivery-kit/issues/7584)) ([a801ed0](https://github.com/deckhouse/delivery-kit/commit/a801ed0a))
* **deploy:** hangs on very long pod lines ([#7580](https://github.com/deckhouse/delivery-kit/issues/7580)) ([daefa02](https://github.com/deckhouse/delivery-kit/commit/daefa02fb7bb1e6146f7f2e6f78db6e7738375ee))
* **deploy:** no more "no match for resource kind" errors ([#7585](https://github.com/deckhouse/delivery-kit/issues/7585)) ([a3d0a5a](https://github.com/deckhouse/delivery-kit/commit/a3d0a5ae7b5110edd6c9ae63b64135b264c6ea31))
* **deploy:** retry also on conversion webhooks unavailability ([#7587](https://github.com/deckhouse/delivery-kit/issues/7587)) ([1623efe](https://github.com/deckhouse/delivery-kit/commit/1623efe0fa246d3b6917786e7033d882101e1391))
* **deploy:** show actual error if webhook retries fail ([#7586](https://github.com/deckhouse/delivery-kit/issues/7586)) ([1dc615e](https://github.com/deckhouse/delivery-kit/commit/1dc615ecc97e1fd25d4ad8f96b2850082bf8a022))

## [2.72.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.71.1-dk...v2.72.0-dk) (2026-06-15)


### Features

* **config:** add packages directive to stapel image configuration ([9e40b37](https://github.com/deckhouse/delivery-kit/commit/9e40b372aaf2e42b9ec46d7ea310ddb035554e54))
* **cleanup:** delete rejected stages and linked custom tags during cleanup/purge ([#7576](https://github.com/deckhouse/delivery-kit/issues/7576)) ([b1b0980](https://github.com/deckhouse/delivery-kit/commit/b1b09809435789ad97dbce60c5a8be2886f0335a))


### Bug Fixes

* **build, buildah:** fix multiarch build failing with "image not known" for cross-platform images ([#7573](https://github.com/deckhouse/delivery-kit/issues/7573)) ([8cd109f](https://github.com/deckhouse/delivery-kit/commit/8cd109fa79cf5e951d409279fad2306f707ca5bb))


### Miscellaneous Chores

* return specific error on elf/sign verify if no section headers ([715cbdb](https://github.com/deckhouse/delivery-kit/commit/715cbdb756dac5fc4b8c12b70ff36d8a14eb869f))

## [2.72.1](https://github.com/werf/werf/compare/v2.72.0...v2.72.1) (2026-06-18)


### Bug Fixes

* **deploy:** hangs on very long pod lines ([#7580](https://github.com/werf/werf/issues/7580)) ([daefa02](https://github.com/werf/werf/commit/daefa02fb7bb1e6146f7f2e6f78db6e7738375ee))
* **deploy:** no more "no match for resource kind" errors ([#7585](https://github.com/werf/werf/issues/7585)) ([a3d0a5a](https://github.com/werf/werf/commit/a3d0a5ae7b5110edd6c9ae63b64135b264c6ea31))
* **deploy:** retry also on conversion webhooks unavailability ([#7587](https://github.com/werf/werf/issues/7587)) ([1623efe](https://github.com/werf/werf/commit/1623efe0fa246d3b6917786e7033d882101e1391))
* **deploy:** show actual error if webhook retries fail ([#7586](https://github.com/werf/werf/issues/7586)) ([1dc615e](https://github.com/werf/werf/commit/1dc615ecc97e1fd25d4ad8f96b2850082bf8a022))

## [2.71.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.71.0-dk...v2.71.1-dk) (2026-06-11)


### Bug Fixes

* **fix(sbom):** skip SBOM generation for trusted builder images ([#103](https://github.com/deckhouse/delivery-kit/issues/103)) ([f796445](https://github.com/deckhouse/delivery-kit/commit/f796445cde4d910df4a9557a4b09c4740ff034e6))

## [2.72.0](https://github.com/werf/werf/compare/v2.71.0...v2.72.0) (2026-06-11)


### Features

* **cleanup:** delete rejected stages and linked custom tags during cleanup/purge ([#7576](https://github.com/werf/werf/issues/7576)) ([b1b0980](https://github.com/werf/werf/commit/b1b09809435789ad97dbce60c5a8be2886f0335a))


### Bug Fixes

* **build, buildah:** fix multiarch build failing with "image not known" for cross-platform images ([#7573](https://github.com/werf/werf/issues/7573)) ([8cd109f](https://github.com/werf/werf/commit/8cd109fa79cf5e951d409279fad2306f707ca5bb))

## [2.71.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.70.1-dk...v2.71.0-dk) (2026-06-10)


### Features

* **build:** add commit to build report for images and stages ([#7566](https://github.com/deckhouse/delivery-kit/issues/7566)) ([38be712](https://github.com/deckhouse/delivery-kit/commit/38be712c95347a247e0ed022f4b624df0bfd3857))
* **sbom:** add external references enrichment ([#98](https://github.com/deckhouse/delivery-kit/issues/98)) ([2fb36a3](https://github.com/deckhouse/delivery-kit/commit/2fb36a38520331825de337d46c40bcfc57d73cc8))
* **sbom:** adopt OCI artifact-based registry-only storage ([574e35b](https://github.com/deckhouse/delivery-kit/commit/574e35be82ca28949885165a0fc51e3310d83c86))


### Bug Fixes

* **build, stapel, import:** importing into symlinked directories no longer silently loses files ([#7545](https://github.com/deckhouse/delivery-kit/issues/7545)) ([9d1bb68](https://github.com/deckhouse/delivery-kit/commit/9d1bb68caae3f55f4b4d3de419eb44653661b47a))
* **deploy:** autodependencies between pods/controllers, rolebindings and serviceaccounts ([#7567](https://github.com/deckhouse/delivery-kit/issues/7567)) ([f152352](https://github.com/deckhouse/delivery-kit/commit/f1523529a7ff3e7e40515dcd1c3e06c10dac13bd))


### Miscellaneous Chores

* **main:** trigger release please ([ba1a3a7](https://github.com/deckhouse/delivery-kit/commit/ba1a3a7169a9a64d21f6e22858e1df28d47fdf30))
* **deps:** bump `copy-recurse` to correctly handle importing into symlinked dirs ([c25568d](https://github.com/deckhouse/delivery-kit/commit/c25568df7f2a1967d8356f8086f8677e6051187f))

## [2.71.0](https://github.com/werf/werf/compare/v2.70.0...v2.71.0) (2026-06-09)


### Features

* **build:** add commit to build report for images and stages ([#7566](https://github.com/werf/werf/issues/7566)) ([38be712](https://github.com/werf/werf/commit/38be712c95347a247e0ed022f4b624df0bfd3857))


### Bug Fixes

* **build, stapel, import:** importing into symlinked directories no longer silently loses files ([#7545](https://github.com/werf/werf/issues/7545)) ([9d1bb68](https://github.com/deckhouse/delivery-kit/commit/9d1bb68caae3f55f4b4d3de419eb44653661b47a))
* **deploy:** autodependencies between pods/controllers, rolebindings and serviceaccounts ([#7567](https://github.com/werf/werf/issues/7567)) ([f152352](https://github.com/deckhouse/delivery-kit/commit/f1523529a7ff3e7e40515dcd1c3e06c10dac13bd))

## [2.70.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.70.0-dk...v2.70.1-dk) (2026-06-05)

### Miscellaneous Chores

* **deps:** bump deckhouse/delivery-kit-sdk to v1.2.1 ([2a35aae](https://github.com/deckhouse/delivery-kit/commit/2a35aae42861babe0829dc04c1060e3b39c64d2c))
* release 2.70.1 ([5232348](https://github.com/deckhouse/delivery-kit/commit/5232348f230ae913bbe9621537e562b7172fdabf))

## [2.70.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.69.0-dk...v2.70.0-dk) (2026-06-03)

## [2.70.0](https://github.com/werf/werf/compare/v2.69.1...v2.70.0) (2026-05-27)


### Features

* **cleanup:** add --kube-scan-namespaces support for in-cluster scan ([#7517](https://github.com/deckhouse/delivery-kit/issues/7517)) ([8941a1e](https://github.com/deckhouse/delivery-kit/commit/8941a1ed470be4265df080e3b87afb61288789b3))


### Bug Fixes

* **build:** eliminate redundant registry tag listing in post-build metadata publication ([#7559](https://github.com/deckhouse/delivery-kit/issues/7559)) ([27404cb](https://github.com/deckhouse/delivery-kit/commit/27404cbddca0e4d8f20680fc8bba4cc5cee8d436))
* **build, stapel:** handle platform mismatch in stage base image resolution and avoid panic ([#7493](https://github.com/deckhouse/delivery-kit/issues/7493)) ([cdf0e83](https://github.com/deckhouse/delivery-kit/commit/cdf0e831b127cd041141aa9ecf951e12056e2135))
* **cleanup:** failing for cross-account ECR repositories ([37c636c](https://github.com/deckhouse/delivery-kit/commit/37c636cb252d765a4c83d901f05b7abd9bf56175))


## [2.69.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.68.2-dk...v2.69.0-dk) (2026-05-21)

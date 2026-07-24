# Changelog

## [2.77.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.76.0-dk...v2.77.0-dk) (2026-07-24)


### Features

* **sbom:** add JavaScript package ecosystem types (npm, yarn, pnpm) ([c70ec68](https://github.com/deckhouse/delivery-kit/commit/c70ec687e5e9b5c2e0966479185801162fb5e336))
* **sbom:** don't enforce pm determnism ([c22beb5](https://github.com/deckhouse/delivery-kit/commit/c22beb5ac70ec3967909ba455bfb7b23617c358b))


### Bug Fixes

* **build, oci:** hide OCI attestation commands from help output ([5a17940](https://github.com/deckhouse/delivery-kit/commit/5a179403d01fb078ebbedf7535875eafb355167e))

## [2.76.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.75.1-dk...v2.76.0-dk) (2026-07-20)


### Features

* **build, oci:** add commands to manage oci artifacts ([#162](https://github.com/deckhouse/delivery-kit/issues/162)) ([61e83fb](https://github.com/deckhouse/delivery-kit/commit/61e83fba05b23ce54527498ce5cb316d57cbfca2))


### Bug Fixes

* **config:** use stapel coreutils in pm snapshot command ([a39429c](https://github.com/deckhouse/delivery-kit/commit/a39429c41524945ee7fffa6c938a3d7f23d497a1))
* **sbom:** read pm files from image without executing coreutils ([252d0c1](https://github.com/deckhouse/delivery-kit/commit/252d0c1a4c41eda79d4217ac4d1f24770bba9d3f))

## [2.75.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.75.0-dk...v2.75.1-dk) (2026-07-17)


### Bug Fixes

* **config:** resolve pm env vars from build secrets in packages stage ([6a744aa](https://github.com/deckhouse/delivery-kit/commit/6a744aaf6e3ba32fbd1e1a2b25bdb9cd1c7646c1))

## [2.75.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.74.2-dk...v2.75.0-dk) (2026-07-17)


### Features

* **config:** enforce determinism for os-pm via spec+lock files ([6cab174](https://github.com/deckhouse/delivery-kit/commit/6cab17481ff9b779ca0793eda098a74635a58654))
* **sbom:** add support for rust-cargo package type ([0411d0b](https://github.com/deckhouse/delivery-kit/commit/0411d0b932497d117048096f9bf2f68c8444d0f6))
* **sbom:** declare lua dependencies via packages directive ([6627dae](https://github.com/deckhouse/delivery-kit/commit/6627daec1f87adb34789ec9024950a6282b46682))
* **sbom:** declare python dependencies via packages directive ([#144](https://github.com/deckhouse/delivery-kit/issues/144)) ([409791c](https://github.com/deckhouse/delivery-kit/commit/409791cbbb510cd052c8731ab351c0b7ec8e8b9a))


### Bug Fixes

* **build:** forward include.path to submodule sync/update commands ([#7660](https://github.com/deckhouse/delivery-kit/issues/7660)) ([5ab32d2](https://github.com/deckhouse/delivery-kit/commit/5ab32d2fd7598bfcdb598f1f1217138e15a9e4b2))
* **sbom:** prevent lack of SBOM completeness in context of trusted ([9fd5088](https://github.com/deckhouse/delivery-kit/commit/9fd508827d2beb720118814705943094ea987a76))
* **sbom:** report all failing components during external ref enrichment ([#177](https://github.com/deckhouse/delivery-kit/issues/177)) ([29f2634](https://github.com/deckhouse/delivery-kit/commit/29f2634a904454f1be9af0299a50258202e0f61c))
* **sbom:** show deprecation warning for alpine builder images ([98df913](https://github.com/deckhouse/delivery-kit/commit/98df91381d394e4e5a4bdc9406684ffecb242b91))

## [2.74.2-dk](https://github.com/deckhouse/delivery-kit/compare/v2.74.1-dk...v2.74.2-dk) (2026-07-10)


### Bug Fixes

* **cleanup:** propagate service labels into mutable stage images ([bbdd116](https://github.com/deckhouse/delivery-kit/commit/bbdd116a684b027534797f591d85ca7de21709cc))

## [2.74.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.74.0-dk...v2.74.1-dk) (2026-07-09)


### Bug Fixes

* **build:** include sbom enable state in stage cache digest ([ba9ad93](https://github.com/deckhouse/delivery-kit/commit/ba9ad938fe161ed0dce376445513b7e96e752c9c))
* **sbom:** dedup external references ([9922129](https://github.com/deckhouse/delivery-kit/commit/9922129e676fbbeafe6970fd6672d4fe9b030bef))

## [2.74.0-dk](https://github.com/deckhouse/delivery-kit/compare/v2.73.2-dk...v2.74.0-dk) (2026-07-07)


### Features

* **deploy:** add `werf.io/resource-policy` annotation ([#7613](https://github.com/deckhouse/delivery-kit/issues/7613)) ([72ae0f2](https://github.com/deckhouse/delivery-kit/commit/72ae0f24ea745a81c61656d1c25df8dace2538f6))
* **sbom:** generate CPE for pm components ([b6298e6](https://github.com/deckhouse/delivery-kit/commit/b6298e6c0f378139594034fd87ac8e741cfbdca6))
* **sbom:** generate metadata for pm components ([5608a29](https://github.com/deckhouse/delivery-kit/commit/5608a2953fac204924dc7db8d0f829173355bae5))


### Bug Fixes

* **deploy:** `werf.io/resource-policy` should only respect skip-delete from live ([#7623](https://github.com/deckhouse/delivery-kit/issues/7623)) ([f261028](https://github.com/deckhouse/delivery-kit/commit/f261028ca4b92b48ef9e26c353c0adade1e331ea))
* **sbom:** use containerFactoryVersion purl qualifier for pm components ([#140](https://github.com/deckhouse/delivery-kit/issues/140)) ([6258e82](https://github.com/deckhouse/delivery-kit/commit/6258e82df787f799618b7dd3f8f92136b7f1aa09))

## [2.73.2-dk](https://github.com/deckhouse/delivery-kit/compare/v2.73.1-dk...v2.73.2-dk) (2026-07-02)


### Bug Fixes

* **build, signing:** stream signed ELF layer instead of buffering ([#143](https://github.com/deckhouse/delivery-kit/issues/143)) ([1770207](https://github.com/deckhouse/delivery-kit/commit/1770207acadc643b2e0e1fa1c35e1b1b406c4f3d))
* **build, stapel:** introspect failed stage from committed image, not temp UUID ([#7607](https://github.com/deckhouse/delivery-kit/issues/7607)) ([a0bc374](https://github.com/deckhouse/delivery-kit/commit/a0bc374892442d3de2ca9e803eeb437996bc7dfd))
* **sign:** sign normalized manifest so verify matches pushed config ([#141](https://github.com/deckhouse/delivery-kit/issues/141)) ([89774d8](https://github.com/deckhouse/delivery-kit/commit/89774d8c04821986b805318ee1c00d153521443e))


### Miscellaneous Chores

* force release 2.73.2-dk ([ea36764](https://github.com/deckhouse/delivery-kit/commit/ea36764b3f2206ab24555b38e6d4f7b62b5c26ea))

## [2.73.1-dk](https://github.com/deckhouse/delivery-kit/compare/v2.72.2-dk...v2.73.1-dk) (2026-06-26)


### Features

* **sbom:** add packages install stage and os-pm SBOM support  ([#135](https://github.com/deckhouse/delivery-kit/issues/135)) ([198c497](https://github.com/deckhouse/delivery-kit/commit/198c4978386f76594b1724c5cf72169feb774ded))
* **sbom:** catalog go.mod packages via go-mod packages directive ([cc0a088](https://github.com/deckhouse/delivery-kit/commit/cc0a088e7bc481d5630e81cd6b089dc03dde0bf1))
* **sbom:** enforce network isolation for Stapel stages when SBOM enabled ([e753409](https://github.com/deckhouse/delivery-kit/commit/e753409afd308c8d052b0480be64ecee0d58b107))
* **sbom:** replace PackageResolveStage with shell-based packages stage ([7260401](https://github.com/deckhouse/delivery-kit/commit/7260401c29203418753c2b68006ae2bba1d9de78))


### Bug Fixes

* **build, buildah, dockerfile, staged:** resolve staged Dockerfile RUN --mount from=&lt;stage&gt; to built image ([#7594](https://github.com/deckhouse/delivery-kit/issues/7594)) ([b1933b3](https://github.com/deckhouse/delivery-kit/commit/b1933b36118fb36a5bab847a93c56bc9196c13b1))
* **build:** use UUID-based naming for scratch base images to prevent buildah misinterpretation ([#7602](https://github.com/deckhouse/delivery-kit/issues/7602)) ([9ce7545](https://github.com/deckhouse/delivery-kit/commit/9ce7545582c59de01789d72c6f56bdf13b1e6a22))


### Miscellaneous Chores

* force release 2.73.0-dk ([c48df85](https://github.com/deckhouse/delivery-kit/commit/c48df853a061d36ce84fe22a5602c1cc5df762a5))
* force release 2.73.1-dk ([2877a2c](https://github.com/deckhouse/delivery-kit/commit/2877a2c645d9ad3baf835ffaee82c51b7176e81a))

## [2.72.2-dk](https://github.com/deckhouse/delivery-kit/compare/v2.72.1-dk...v2.72.2-dk) (2026-06-19)


### Features

* **deploy:** move `dockerconfigjson` to .global.werf ([#7583](https://github.com/deckhouse/delivery-kit/issues/7583)) ([79d90cb](https://github.com/deckhouse/delivery-kit/commit/79d90cb69f563a2ec7b109de5481c4eba45f9722))


### Bug Fixes

* **build, stapel, import:** rsync chown "/sys" Read-only file system on to: / ([#7590](https://github.com/deckhouse/delivery-kit/issues/7590)) ([b6dac9c](https://github.com/deckhouse/delivery-kit/commit/b6dac9c9835e5a9d3745f865ee5ab3944828f6c4))
* **ci:** switch release-please to manifest mode, fix upstream werf baseline contamination ([#124](https://github.com/deckhouse/delivery-kit/issues/124)) ([f00cd16](https://github.com/deckhouse/delivery-kit/commit/f00cd165b9189bee3e26b4f60121888c307b7f7d))


### Miscellaneous Chores

* force release 2.72.2-dk ([bf07747](https://github.com/deckhouse/delivery-kit/commit/bf07747173d37c9ca2d99e3b5b4422c2ea5a4959))

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

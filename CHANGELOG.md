# Changelog

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

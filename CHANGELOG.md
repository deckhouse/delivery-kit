# Changelog

## [2.77.1-dk.5](https://github.com/deckhouse/delivery-kit/compare/v2.77.0-dk.5...v2.77.1-dk.5) (2026-08-31)


### Bug Fixes

* **build:** handle cached image descriptors safely ([a891ed4](https://github.com/deckhouse/delivery-kit/commit/a891ed411064223ece5fdf85edce02a85fe73c51))
* **sbom, externalref:** show package purl in SBOM enrichment errors ([080c23d](https://github.com/deckhouse/delivery-kit/commit/080c23d26bf0bd477d9a7acb894b33b92e56666c))
* **sbom, vex:** guard VEX descriptors and remove kube flags from sbom ([efbc794](https://github.com/deckhouse/delivery-kit/commit/efbc794ee915fcbf9814b437d033b94cc1d4fda2))
* **sbom:** regenerate the SBOM when the GOST configuration changes ([#271](https://github.com/deckhouse/delivery-kit/issues/271)) ([5d74fbe](https://github.com/deckhouse/delivery-kit/commit/5d74fbed7ba0c874bfde3a538c89dc143394ab9b))
* **vex:** qualify multiplatform fixture image ([01dc9b0](https://github.com/deckhouse/delivery-kit/commit/01dc9b0dff779ef24637dffea85994fa19fffffe))

## [3.2.0-dk.2](https://github.com/deckhouse/delivery-kit/compare/v3.2.0-dk.1...v3.2.0-dk.2) (2026-08-31)


### Features

* **sbom, attest:** sign multi-platform SBOMs, verify every platform ([#262](https://github.com/deckhouse/delivery-kit/issues/262)) ([655c9fa](https://github.com/deckhouse/delivery-kit/commit/655c9fab80454b0ffbc8f065c1fef79efdb76532))
* **sbom, attest:** sign sbom during build with cosign compatibility ([#230](https://github.com/deckhouse/delivery-kit/issues/230)) ([2521b4e](https://github.com/deckhouse/delivery-kit/commit/2521b4e7f13d7d246358ec35880b3d9982a77271))
* **sbom:** expose pm index version as a component property ([#258](https://github.com/deckhouse/delivery-kit/issues/258)) ([13c2b4e](https://github.com/deckhouse/delivery-kit/commit/13c2b4e0158c3c21108eb051e75358d545fa4c64))
* **sbom:** generate SBOM per platform for multi-platform images ([#232](https://github.com/deckhouse/delivery-kit/issues/232)) ([c6aaf47](https://github.com/deckhouse/delivery-kit/commit/c6aaf475cc51719e5936ac908d384b1d5c27e413))
* **vex, sbom, attest:** sign VEX documents at build time ([#267](https://github.com/deckhouse/delivery-kit/issues/267)) ([ad1b168](https://github.com/deckhouse/delivery-kit/commit/ad1b1688ff640aa86c3d438e3191617e28679b5e))
* **vex:** add VEX lifecycle ([#218](https://github.com/deckhouse/delivery-kit/issues/218)) ([596f3c1](https://github.com/deckhouse/delivery-kit/commit/596f3c151a8bc263a77ead4799fea31c2c5ab690))


### Bug Fixes

* **build, sbom:** warn about disabled network once, in the run summary ([e2a9f35](https://github.com/deckhouse/delivery-kit/commit/e2a9f35464124ffdd866e9156a6b2adb03e37719))
* **build:** handle cached image descriptors safely ([a891ed4](https://github.com/deckhouse/delivery-kit/commit/a891ed411064223ece5fdf85edce02a85fe73c51))
* **image:** parse digest references correctly ([#245](https://github.com/deckhouse/delivery-kit/issues/245)) ([8201b1b](https://github.com/deckhouse/delivery-kit/commit/8201b1b6ef6a4098ca5e9ed0d3a6d53254ec15a7))
* **release:** restore release automation on main ([#249](https://github.com/deckhouse/delivery-kit/issues/249)) ([60acbdf](https://github.com/deckhouse/delivery-kit/commit/60acbdfb54942763a12e75c67cb20787b0203aed))
* **sbom, vex:** guard VEX descriptors and remove kube flags from sbom ([efbc794](https://github.com/deckhouse/delivery-kit/commit/efbc794ee915fcbf9814b437d033b94cc1d4fda2))
* **sbom:** drop internal builder label from missing-SBOM error ([297ec29](https://github.com/deckhouse/delivery-kit/commit/297ec296ac8dc56ea26d34df3ad65dc549cb9711))
* **sbom:** ensure single os-pm config section ([#264](https://github.com/deckhouse/delivery-kit/issues/264)) ([afb3882](https://github.com/deckhouse/delivery-kit/commit/afb3882d845c035535fe72f0c63f225aefed3a04))
* **sbom:** reject PM_LOCK_FILE env ([#265](https://github.com/deckhouse/delivery-kit/issues/265)) ([4709e65](https://github.com/deckhouse/delivery-kit/commit/4709e65a825528be8058fbf3e8a648c10363ee74))
* **sbom:** report real causes and fail fast when PURL resolution fails ([#260](https://github.com/deckhouse/delivery-kit/issues/260)) ([9b2d351](https://github.com/deckhouse/delivery-kit/commit/9b2d351ad0c1422933fb509c88a79027db7351bb))
* **sbom:** skip images importing from an image whose SBOM enrichment failed ([#268](https://github.com/deckhouse/delivery-kit/issues/268)) ([411148b](https://github.com/deckhouse/delivery-kit/commit/411148bca0e6144cb4a0a76f6640208c6992d746))
* **sbom:** use inline pm syntax again ([#254](https://github.com/deckhouse/delivery-kit/issues/254)) ([28082ac](https://github.com/deckhouse/delivery-kit/commit/28082ac62f94a6a20f3439e7d79ae4240b3ef59c))
* **sbom:** warn about missing stageDependencies for file-based packages ([#263](https://github.com/deckhouse/delivery-kit/issues/263)) ([17d44ab](https://github.com/deckhouse/delivery-kit/commit/17d44abfaabfcffd4226cd24b7f17ce92c1afb22))
* **vex:** qualify multiplatform fixture image ([01dc9b0](https://github.com/deckhouse/delivery-kit/commit/01dc9b0dff779ef24637dffea85994fa19fffffe))

## [2.77.0-dk.5](https://github.com/deckhouse/delivery-kit/compare/v2.77.0-dk.4...v2.77.0-dk.5) (2026-08-25)


### Features

* **sbom, attest:** sign multi-platform SBOMs, verify every platform ([#262](https://github.com/deckhouse/delivery-kit/issues/262)) ([655c9fa](https://github.com/deckhouse/delivery-kit/commit/655c9fab80454b0ffbc8f065c1fef79efdb76532))
* **vex, sbom, attest:** sign VEX documents at build time ([#267](https://github.com/deckhouse/delivery-kit/issues/267)) ([ad1b168](https://github.com/deckhouse/delivery-kit/commit/ad1b1688ff640aa86c3d438e3191617e28679b5e))


### Bug Fixes

* **sbom:** skip images importing from an image whose SBOM enrichment failed ([#268](https://github.com/deckhouse/delivery-kit/issues/268)) ([411148b](https://github.com/deckhouse/delivery-kit/commit/411148bca0e6144cb4a0a76f6640208c6992d746))

## [3.2.0-dk.1](https://github.com/deckhouse/delivery-kit/compare/v3.1.0-dk.1...v3.2.0-dk.1) (2026-08-11)


### Features

* add case-insensitive-condition-tracking feature gate ([#7801](https://github.com/deckhouse/delivery-kit/issues/7801)) ([8043316](https://github.com/deckhouse/delivery-kit/commit/8043316e0dc688d145627adb035254880fba309a))
* **build:** show low-level operations time summary in debug mode ([#7675](https://github.com/deckhouse/delivery-kit/issues/7675)) ([4f65aef](https://github.com/deckhouse/delivery-kit/commit/4f65aefeafd28e5692ec4d37f7a9e9f69d65c5d3))
* **cleanup:** add registry-side cleanup report ([#7806](https://github.com/deckhouse/delivery-kit/issues/7806)) ([8a6250b](https://github.com/deckhouse/delivery-kit/commit/8a6250b3dbd5f4406a38fe4c42630a6244da8f14))
* **cleanup:** name the --meta-repo address in the cleanup report ([c11fdfb](https://github.com/deckhouse/delivery-kit/commit/c11fdfbd8161779d957347a76dab8e216ff9afd6))
* **deploy:** embed deno binary into werf release binaries behind `embedwerfdeno` ([#7725](https://github.com/deckhouse/delivery-kit/issues/7725)) ([468ba22](https://github.com/deckhouse/delivery-kit/commit/468ba229e05e7fb104a286386da43e0051da09ed))
* **skills:** prevent agents publishing stale claims ([f8d938a](https://github.com/deckhouse/delivery-kit/commit/f8d938aec732b43c6509abbb972ac60c8a198814))
* **skills:** prevent agents publishing stale claims ([#7780](https://github.com/deckhouse/delivery-kit/issues/7780)) ([78b4ac78b8d621c04d8eee2d10067cf7c1813100))
* **skills:** run challenge checks for risky reviews ([#7781](https://github.com/deckhouse/delivery-kit/issues/7781)) ([d16b172](https://github.com/deckhouse/delivery-kit/commit/d16b172013995186b30276788ef72a09338d35f4))


### Bug Fixes

* **build, buildah:** prevent parallel recovery failures ([#7774](https://github.com/deckhouse/delivery-kit/issues/7774)) ([fd5758d](https://github.com/deckhouse/delivery-kit/commit/fd5758dcfeed86ed3c2e245f4630daf68299896f))
* **build, buildah:** retry pull when cached image id is missing ([#7669](https://github.com/deckhouse/delivery-kit/issues/7669)) ([9d64035](https://github.com/deckhouse/delivery-kit/commit/9d640357576a029456d94516b64c0eda1214025a))
* **build, sbom:** stop panicking on images reused from the cache ([4e2f356](https://github.com/deckhouse/delivery-kit/commit/4e2f3566bd0db09b5cf398e53bc3a24cac19a324))
* **buildah:** prevent concurrent Dockerfile build races ([#7798](https://github.com/deckhouse/delivery-kit/issues/7798)) ([f609194](https://github.com/deckhouse/delivery-kit/commit/f60919448a7c93f08f5706678bd016e2806677fa))
* **buildah:** prevent concurrent stderr access ([#7788](https://github.com/deckhouse/delivery-kit/issues/7788)) ([fc9c375](https://github.com/deckhouse/delivery-kit/commit/fc9c3759a8f6bf61aa98eef526d21a8315f04b1a))
* **build:** avoid panicking on late worker logs ([#7785](https://github.com/deckhouse/delivery-kit/issues/7785)) ([4a89693](https://github.com/deckhouse/delivery-kit/commit/4a89693e2261a60c44bb7c1023f2a1b4647bbd51))
* **build:** keep concurrent Dockerfile builds parallel under race fix ([#7803](https://github.com/deckhouse/delivery-kit/issues/7803)) ([f759bec](https://github.com/deckhouse/delivery-kit/commit/f759becbb7a5694c237ee51a20a236a7d5286b3e))
* **build:** make repo-built from:scratch images readable by dive ([#7765](https://github.com/deckhouse/delivery-kit/issues/7765)) ([54b0921](https://github.com/deckhouse/delivery-kit/commit/54b092177796f41c5fce2944f4bf73f45e058da8))
* **buildx:** restore concurrent Dockerfile builds ([#7800](https://github.com/deckhouse/delivery-kit/issues/7800)) ([0d1c7ee](https://github.com/deckhouse/delivery-kit/commit/0d1c7ee77b1b6f0a9ba65d6a60d2506a8e491685))
* **ci:** stop rootless buildah CI builds failing ([#7782](https://github.com/deckhouse/delivery-kit/issues/7782)) ([990bdab](https://github.com/deckhouse/delivery-kit/commit/990bdabc9fa6eaad5bbf4122bdf7c001e27f1904))
* **ci:** stop rootless buildah e2e builds failing ([#7783](https://github.com/deckhouse/delivery-kit/issues/7783)) ([9e37b96](https://github.com/deckhouse/delivery-kit/commit/9e37b96c4d0fbbfcabb2926bc0cb4c0faa13c59e))
* **deploy:** prevent progress printer race during release tracking ([#7805](https://github.com/deckhouse/delivery-kit/issues/7805)) ([1b46987](https://github.com/deckhouse/delivery-kit/commit/1b469876339bddaefdb12d456708bc9194d35f2f))
* **docker:** prevent race reports during Docker builds ([#7777](https://github.com/deckhouse/delivery-kit/issues/7777)) ([6d6af8d](https://github.com/deckhouse/delivery-kit/commit/6d6af8d02be5f1a58e5dc8806c7e64d5c9f150c6))
* **helm:** prevent concurrent action initialization ([#7793](https://github.com/deckhouse/delivery-kit/issues/7793)) ([d57cc9e](https://github.com/deckhouse/delivery-kit/commit/d57cc9e7259d0e964721fcd6573eadec060a3971))
* **helm:** prevent concurrent action initialization ([#7796](https://github.com/deckhouse/delivery-kit/issues/7796)) ([bad9bfd](https://github.com/deckhouse/delivery-kit/commit/bad9bfd0f8761832da5b19f241dc4cd85d12d8b4))
* **logboek:** prevent concurrent stream races ([#7802](https://github.com/deckhouse/delivery-kit/issues/7802)) ([f80e827](https://github.com/deckhouse/delivery-kit/commit/f80e827577896f02d3605b3c7540d550e31f8e0a))
* optimize `release get` ([8043316](https://github.com/deckhouse/delivery-kit/commit/8043316e0dc688d145627adb035254880fba309a))
* **registry:** prevent concurrent export races ([#7799](https://github.com/deckhouse/delivery-kit/issues/7799)) ([2bf41ec](https://github.com/deckhouse/delivery-kit/commit/2bf41ecf9af9a54576cb13465816e0de977ff1d5))
* **release:** preserve main release version state ([#7790](https://github.com/deckhouse/delivery-kit/issues/7790)) ([a0603b294c829abb510f938bd7817a8314bc144c))
* **release:** preserve v3 release version state ([#7789](https://github.com/deckhouse/delivery-kit/issues/7789)) ([4b6564f](https://github.com/deckhouse/delivery-kit/commit/4b6564f7ff19484151640dc631ae23bfd83b8fe3))
* **sbom:** add help link hint to aggregated PURL resolve error ([#233](https://github.com/deckhouse/delivery-kit/issues/233)) ([5dff183](https://github.com/deckhouse/delivery-kit/commit/5dff1830522142cccf61a5f9f3db29edc849428a))
* **sbom:** converge the artifact index instead of failing on a lost update ([909edc0](https://github.com/deckhouse/delivery-kit/commit/909edc0a8b0b919bf6ecb72432bff5c475656bcc))
* **sbom:** enforce pm determinism again ([#226](https://github.com/deckhouse/delivery-kit/issues/226)) ([c6b0349](https://github.com/deckhouse/delivery-kit/commit/c6b03498bfa10ef9ae94ef2e549189f235b778dd))
* **sbom:** propagate attached artifacts along stage copies ([#240](https://github.com/deckhouse/delivery-kit/issues/240)) ([6e40074](https://github.com/deckhouse/delivery-kit/commit/6e40074fa87e63fa504c32f8a874e55fc7665f75))
* **storage:** prevent concurrent final-stage list access ([#7787](https://github.com/deckhouse/delivery-kit/issues/7787)) ([9ab8115](https://github.com/deckhouse/delivery-kit/commit/9ab81159f2c87abf50d1caa8d2f2bbe5cff7ca55))


### Miscellaneous Chores

* force release 2.75.4-dk.1 ([1ec2055](https://github.com/deckhouse/delivery-kit/commit/1ec205529ed9395e21a5a4cb3b0b77ec9fb097d2))
* force release 2.77.0-dk.1 ([c0c72f6](https://github.com/deckhouse/delivery-kit/commit/c0c72f6e425f1abaa0550f83476e6056e2f1b35f))
* force release 3.2.0-dk.1 ([b3b0cb3](https://github.com/deckhouse/delivery-kit/commit/b3b0cb3c539dff7273e32ed65ecc938759ed1bf4))

## [2.77.0-dk.4](https://github.com/deckhouse/delivery-kit/compare/v2.77.0-dk.3...v2.77.0-dk.4) (2026-08-21)


### Features

* **sbom:** expose pm index version as a component property ([#258](https://github.com/deckhouse/delivery-kit/issues/258)) ([13c2b4e](https://github.com/deckhouse/delivery-kit/commit/13c2b4e0158c3c21108eb051e75358d545fa4c64))


### Bug Fixes

* **sbom:** ensure single os-pm config section ([#264](https://github.com/deckhouse/delivery-kit/issues/264)) ([afb3882](https://github.com/deckhouse/delivery-kit/commit/afb3882d845c035535fe72f0c63f225aefed3a04))
* **sbom:** reject PM_LOCK_FILE env ([#265](https://github.com/deckhouse/delivery-kit/issues/265)) ([4709e65](https://github.com/deckhouse/delivery-kit/commit/4709e65a825528be8058fbf3e8a648c10363ee74))
* **sbom:** report real causes and fail fast when PURL resolution fails ([#260](https://github.com/deckhouse/delivery-kit/issues/260)) ([9b2d351](https://github.com/deckhouse/delivery-kit/commit/9b2d351ad0c1422933fb509c88a79027db7351bb))
* **sbom:** warn about missing stageDependencies for file-based packages ([#263](https://github.com/deckhouse/delivery-kit/issues/263)) ([17d44ab](https://github.com/deckhouse/delivery-kit/commit/17d44abfaabfcffd4226cd24b7f17ce92c1afb22))

## [2.77.0-dk.3](https://github.com/deckhouse/delivery-kit/compare/v2.77.0-dk.2...v2.77.0-dk.3) (2026-08-18)


### Features

* **sbom:** generate SBOM per platform for multi-platform images ([#232](https://github.com/deckhouse/delivery-kit/issues/232)) ([c6aaf47](https://github.com/deckhouse/delivery-kit/commit/c6aaf475cc51719e5936ac908d384b1d5c27e413))


### Bug Fixes

* **build, sbom:** warn about disabled network once, in the run summary ([e2a9f35](https://github.com/deckhouse/delivery-kit/commit/e2a9f35464124ffdd866e9156a6b2adb03e37719))
* **sbom:** use inline pm syntax again ([#254](https://github.com/deckhouse/delivery-kit/issues/254)) ([28082ac](https://github.com/deckhouse/delivery-kit/commit/28082ac62f94a6a20f3439e7d79ae4240b3ef59c))

## [2.77.0-dk.2](https://github.com/deckhouse/delivery-kit/compare/v2.77.0-dk.1...v2.77.0-dk.2) (2026-08-13)


### Features

* **sbom, attest:** sign sbom during build with cosign compatibility ([#230](https://github.com/deckhouse/delivery-kit/issues/230)) ([2521b4e](https://github.com/deckhouse/delivery-kit/commit/2521b4e7f13d7d246358ec35880b3d9982a77271))
* **vex:** add VEX lifecycle ([#218](https://github.com/deckhouse/delivery-kit/issues/218)) ([596f3c1](https://github.com/deckhouse/delivery-kit/commit/596f3c151a8bc263a77ead4799fea31c2c5ab690))


### Bug Fixes

* **image:** parse digest references correctly ([#245](https://github.com/deckhouse/delivery-kit/issues/245)) ([8201b1b](https://github.com/deckhouse/delivery-kit/commit/8201b1b6ef6a4098ca5e9ed0d3a6d53254ec15a7))
* **release:** restore release automation on main ([#249](https://github.com/deckhouse/delivery-kit/issues/249)) ([60acbdf](https://github.com/deckhouse/delivery-kit/commit/60acbdfb54942763a12e75c67cb20787b0203aed))
* **sbom:** drop internal builder label from missing-SBOM error ([297ec29](https://github.com/deckhouse/delivery-kit/commit/297ec296ac8dc56ea26d34df3ad65dc549cb9711))

## [2.77.0-dk.1](https://github.com/deckhouse/delivery-kit/compare/v2.75.4-dk.3...v2.77.0-dk.1) (2026-08-11)


### Miscellaneous Chores

* force release 2.77.0-dk.1 ([c0c72f6](https://github.com/deckhouse/delivery-kit/commit/c0c72f6e425f1abaa0550f83476e6056e2f1b35f))

## [2.75.4-dk.3](https://github.com/deckhouse/delivery-kit/compare/v2.75.4-dk.2...v2.75.4-dk.3) (2026-08-11)


### Bug Fixes

* **sbom:** propagate attached artifacts along stage copies ([#240](https://github.com/deckhouse/delivery-kit/issues/240)) ([6e40074](https://github.com/deckhouse/delivery-kit/commit/6e40074fa87e63fa504c32f8a874e55fc7665f75))

## [2.75.4-dk.2](https://github.com/deckhouse/delivery-kit/compare/v2.75.4-dk.1...v2.75.4-dk.2) (2026-08-07)


### Bug Fixes

* **sbom:** add help link hint to aggregated PURL resolve error ([#233](https://github.com/deckhouse/delivery-kit/issues/233)) ([5dff183](https://github.com/deckhouse/delivery-kit/commit/5dff1830522142cccf61a5f9f3db29edc849428a))
* **sbom:** enforce pm determinism again ([#226](https://github.com/deckhouse/delivery-kit/issues/226)) ([c6b0349](https://github.com/deckhouse/delivery-kit/commit/c6b03498bfa10ef9ae94ef2e549189f235b778dd))

## [2.75.4-dk.1](https://github.com/deckhouse/delivery-kit/compare/v2.75.3-dk.1...v2.75.4-dk.1) (2026-08-06)


### Features

* **sbom:** add language pkg env vars ([#220](https://github.com/deckhouse/delivery-kit/issues/220)) ([e42596e](https://github.com/deckhouse/delivery-kit/commit/e42596ee08f300cc914743165fa7ffe3cd5bb6e6))
* **sbom:** support environment variables for os-pm ([#217](https://github.com/deckhouse/delivery-kit/issues/217)) ([8bc1d20](https://github.com/deckhouse/delivery-kit/commit/8bc1d204d0fd54037b4a6285aa6d75f892178d4b))


### Bug Fixes

* **build, buildah:** retry pull when cached image id is missing ([#7669](https://github.com/deckhouse/delivery-kit/issues/7669)) ([9d64035](https://github.com/deckhouse/delivery-kit/commit/9d640357576a029456d94516b64c0eda1214025a))
* **build, buildah:** serialize concurrent base image pulls ([#7664](https://github.com/deckhouse/delivery-kit/issues/7664)) ([6eb9144](https://github.com/deckhouse/delivery-kit/commit/6eb9144a1f0b71b6c6df3d5ec8ba8b6d3bd14b82))
* **build, stapel:** make service script executable regardless of umask ([#7720](https://github.com/deckhouse/delivery-kit/issues/7720)) ([8b67264](https://github.com/deckhouse/delivery-kit/commit/8b67264f781b361119a9d6be0a390afec616e258)), closes [#2339](https://github.com/deckhouse/delivery-kit/issues/2339)
* **build:** drop empty image digest warnings from the build report ([#7717](https://github.com/deckhouse/delivery-kit/issues/7717)) ([24babbb](https://github.com/deckhouse/delivery-kit/commit/24babbbbb2bde473e45a1a8bd72c3ff4c64ea532)), closes [#7667](https://github.com/deckhouse/delivery-kit/issues/7667)
* **build:** make repo-built from:scratch images readable by dive ([#7765](https://github.com/deckhouse/delivery-kit/issues/7765)) ([54b0921](https://github.com/deckhouse/delivery-kit/commit/54b092177796f41c5fce2944f4bf73f45e058da8))
* **sbom:** prevent storage fallback inconsistency ([#210](https://github.com/deckhouse/delivery-kit/issues/210)) ([c690a26](https://github.com/deckhouse/delivery-kit/commit/c690a26cc79251ac01c8b1ffa99fd973a93360a6))
* **sbom:** use default registry auth in GetAttachedContentAny ([34f1658](https://github.com/deckhouse/delivery-kit/commit/34f1658160cf710f70bf3e11cee7200b0809a9ca2))


### Miscellaneous Chores

* force release 2.75.4-dk.1 ([1ec2055](https://github.com/deckhouse/delivery-kit/commit/1ec205529ed9395e21a5a4cb3b0b77ec9fb097d2))

## [3.1.0-dk.1](https://github.com/deckhouse/delivery-kit/compare/v2.75.3-dk.1...v3.1.0-dk.1) (2026-08-05)


### Features

* `--no-values-schema-validation`; don't break values.schema.json with service values ([#7756](https://github.com/deckhouse/delivery-kit/issues/7756)) ([01eeb94](https://github.com/deckhouse/delivery-kit/commit/01eeb94fd129f01ce0c72176a61e3b5ad42f4f91))
* add support for additional patches files and disable default patches ([#7735](https://github.com/deckhouse/delivery-kit/issues/7735)) ([01aa2e5](https://github.com/deckhouse/delivery-kit/commit/01aa2e5c95689aaaeceff151df1b8760938be43c))
* **build:** add per-project meta-repo safeguard and migration ([#7739](https://github.com/deckhouse/delivery-kit/issues/7739)) ([4f7de94](https://github.com/deckhouse/delivery-kit/commit/4f7de9471e73996cd7676cd02b7d4fe2b3aeb7ff))
* bump nelm version ([#7731](https://github.com/deckhouse/delivery-kit/issues/7731)) ([ca44562](https://github.com/deckhouse/delivery-kit/commit/ca44562abe4986a1e66914a5fde8c6e49d5d4c57))
* embed kubeconform schemas ([#7729](https://github.com/deckhouse/delivery-kit/issues/7729)) ([23bcaf1](https://github.com/deckhouse/delivery-kit/commit/23bcaf185d1034a376a1a692228408f81ceeb562))
* **sbom:** add language pkg env vars ([#220](https://github.com/deckhouse/delivery-kit/issues/220)) ([e42596e](https://github.com/deckhouse/delivery-kit/commit/e42596ee08f300cc914743165fa7ffe3cd5bb6e6))
* **sbom:** support environment variables for os-pm ([#217](https://github.com/deckhouse/delivery-kit/issues/217)) ([8bc1d20](https://github.com/deckhouse/delivery-kit/commit/8bc1d204d0fd54037b4a6285aa6d75f892178d4b))


### Bug Fixes

* **build, buildah:** serialize concurrent base image pulls ([#7664](https://github.com/deckhouse/delivery-kit/issues/7664)) ([6eb9144](https://github.com/deckhouse/delivery-kit/commit/6eb9144a1f0b71b6c6df3d5ec8ba8b6d3bd14b82))
* **build, dockerfile:** allow dockerfile outside the build context ([#7722](https://github.com/deckhouse/delivery-kit/issues/7722)) ([a5c2011](https://github.com/deckhouse/delivery-kit/commit/a5c2011e32b9764405ec935c811d7bf6bd3c19e1))
* **build, sbom:** preserve cache behavior with content anchors ([e4d6cd1](https://github.com/deckhouse/delivery-kit/commit/e4d6cd1937a39b7c60992ada2aabe21e5061aa65))
* **build, sbom:** reject inert packages stage dependencies ([fda6ac3](https://github.com/deckhouse/delivery-kit/commit/fda6ac3f3531d09b6c78a1859aae68a0c31cf472))
* **build, sbom:** stop SBOM builds panicking on v3 ([ece4cc6](https://github.com/deckhouse/delivery-kit/commit/ece4cc6aaa0fa19598584fa313ba7f02a53b11c6))
* **build, signing:** stop signed builds panicking on v3 ([b41f07d](https://github.com/deckhouse/delivery-kit/commit/b41f07de439c92303f28711bbdae31c002d54115))
* **build, stapel, git:** remove git commit ancestry check on reuse ([#7746](https://github.com/deckhouse/delivery-kit/issues/7746)) ([544a07d](https://github.com/deckhouse/delivery-kit/commit/544a07d58a4ddb1ad4d2cc94b135571d895a38bb))
* **build, stapel:** make service script executable regardless of umask ([#7720](https://github.com/deckhouse/delivery-kit/issues/7720)) ([8b67264](https://github.com/deckhouse/delivery-kit/commit/8b67264f781b361119a9d6be0a390afec616e258)), closes [#2339](https://github.com/deckhouse/delivery-kit/issues/2339)
* **build:** assign per-image build-log progress index by real start order ([#7703](https://github.com/deckhouse/delivery-kit/issues/7703)) ([7420f5f](https://github.com/deckhouse/delivery-kit/commit/7420f5f5adee048916eb753dcd5e01d6b352e61e))
* **build:** drop empty image digest warnings from the build report ([#7717](https://github.com/deckhouse/delivery-kit/issues/7717)) ([24babbb](https://github.com/deckhouse/delivery-kit/commit/24babbbbb2bde473e45a1a8bd72c3ff4c64ea532)), closes [#7667](https://github.com/deckhouse/delivery-kit/issues/7667)
* **build:** reuse content anchors without git commits ([#7764](https://github.com/deckhouse/delivery-kit/issues/7764)) ([5df466c](https://github.com/deckhouse/delivery-kit/commit/5df466c618c91083d17ecd919c04df79b5eb7522))
* **build:** reuse content anchors without git commits ([#7764](https://github.com/deckhouse/delivery-kit/issues/7764)) ([ea66ed8](https://github.com/deckhouse/delivery-kit/commit/ea66ed8b9980e3af6f463232e505562f25df8857))
* **build:** stop re-fetching submodules the checkout already has ([#7736](https://github.com/deckhouse/delivery-kit/issues/7736)) ([8ff0bf3](https://github.com/deckhouse/delivery-kit/commit/8ff0bf37050bae2837111a71a34cb15365033631))
* **build:** validate image names in werf.yaml ([#7711](https://github.com/deckhouse/delivery-kit/issues/7711)) ([cd993db](https://github.com/deckhouse/delivery-kit/commit/cd993dbc6144c88bf10e852fd9406dac117718e1))
* **deploy:** optimize local validation args ([#7760](https://github.com/deckhouse/delivery-kit/issues/7760)) ([6a4c6c4](https://github.com/deckhouse/delivery-kit/commit/6a4c6c48f9a06d0f44a84754974848ad93cae206))
* **deploy:** optimize local validation args ([#7760](https://github.com/deckhouse/delivery-kit/issues/7760)) ([beb4de1](https://github.com/deckhouse/delivery-kit/commit/beb4de16867e49b75d53de21d795e6043ac23ad8))
* **dev:** make CLI docs generation environment-independent ([572168c](https://github.com/deckhouse/delivery-kit/commit/572168c082107de4f5233a5ebe36cfe552ad77ad))
* **dev:** self-heal a stale worktree index.lock left by a killed run ([#7733](https://github.com/deckhouse/delivery-kit/issues/7733)) ([ca0e803](https://github.com/deckhouse/delivery-kit/commit/ca0e80365bc5ed06ebd112fdfca9ea82ad3328a3))
* **dev:** warm a persistent dev-index so --dev stops re-reading unchanged files ([#7732](https://github.com/deckhouse/delivery-kit/issues/7732)) ([f0b13cc](https://github.com/deckhouse/delivery-kit/commit/f0b13cc264af219d19b04ecfcb40fa2383c94aa5))
* **sbom:** prevent storage fallback inconsistency ([#210](https://github.com/deckhouse/delivery-kit/issues/210)) ([c690a26](https://github.com/deckhouse/delivery-kit/commit/c690a26cc79251ac01c8b1ffa99fd973a93360a6))
* **sbom:** read os-pm secrets with stapel head, not the removed cat ([2a33672](https://github.com/deckhouse/delivery-kit/commit/2a3367286ae6f64a6633b0f36c9ec8dae5123b06))


### Miscellaneous Chores

* force release 3.0.0-test.1-dk.1 ([4da7b3d](https://github.com/deckhouse/delivery-kit/commit/4da7b3deb43796a4e114fdacf9e1f2b244db1a89))
* force release 3.1.0-dk.1 ([37c8c65](https://github.com/deckhouse/delivery-kit/commit/37c8c65b99bcfab2192e0f71481f23cd83d0ee41))
* **release:** test release ([#7759](https://github.com/deckhouse/delivery-kit/issues/7759)) ([c4d8079](https://github.com/deckhouse/delivery-kit/commit/c4d80799894e5ac8f2ac6a89f99f54221bc7a3b1))

## [3.0.0-test.1](https://github.com/werf/werf/compare/v3.0.2...v3.0.0-test.1) (2026-08-05)


### Features

* `--no-values-schema-validation`; don't break values.schema.json with service values ([#7756](https://github.com/werf/werf/issues/7756)) ([01eeb94](https://github.com/werf/werf/commit/01eeb94fd129f01ce0c72176a61e3b5ad42f4f91))
* add support for additional patches files and disable default patches ([#7735](https://github.com/werf/werf/issues/7735)) ([01aa2e5](https://github.com/werf/werf/commit/01aa2e5c95689aaaeceff151df1b8760938be43c))
* bump nelm version ([#7731](https://github.com/werf/werf/issues/7731)) ([ca44562](https://github.com/werf/werf/commit/ca44562abe4986a1e66914a5fde8c6e49d5d4c57))
* embed kubeconform schemas ([#7729](https://github.com/werf/werf/issues/7729)) ([23bcaf1](https://github.com/werf/werf/commit/23bcaf185d1034a376a1a692228408f81ceeb562))


### Bug Fixes

* **build, dockerfile:** allow dockerfile outside the build context ([#7722](https://github.com/werf/werf/issues/7722)) ([a5c2011](https://github.com/werf/werf/commit/a5c2011e32b9764405ec935c811d7bf6bd3c19e1))
* **build, stapel, git:** remove git commit ancestry check on reuse ([#7746](https://github.com/werf/werf/issues/7746)) ([544a07d](https://github.com/werf/werf/commit/544a07d58a4ddb1ad4d2cc94b135571d895a38bb))
* **build, stapel:** make service script executable regardless of umask ([#7720](https://github.com/werf/werf/issues/7720)) ([8b67264](https://github.com/werf/werf/commit/8b67264f781b361119a9d6be0a390afec616e258)), closes [#2339](https://github.com/werf/werf/issues/2339)
* **build:** drop empty image digest warnings from the build report ([#7717](https://github.com/werf/werf/issues/7717)) ([24babbb](https://github.com/werf/werf/commit/24babbbbb2bde473e45a1a8bd72c3ff4c64ea532)), closes [#7667](https://github.com/werf/werf/issues/7667)
* **build:** stop re-fetching submodules the checkout already has ([#7736](https://github.com/werf/werf/issues/7736)) ([8ff0bf3](https://github.com/werf/werf/commit/8ff0bf37050bae2837111a71a34cb15365033631))
* **build:** validate image names in werf.yaml ([#7711](https://github.com/werf/werf/issues/7711)) ([cd993db](https://github.com/werf/werf/commit/cd993dbc6144c88bf10e852fd9406dac117718e1))
* **dev:** self-heal a stale worktree index.lock left by a killed run ([#7733](https://github.com/werf/werf/issues/7733)) ([ca0e803](https://github.com/werf/werf/commit/ca0e80365bc5ed06ebd112fdfca9ea82ad3328a3))
* **dev:** warm a persistent dev-index so --dev stops re-reading unchanged files ([#7732](https://github.com/werf/werf/issues/7732)) ([f0b13cc](https://github.com/werf/werf/commit/f0b13cc264af219d19b04ecfcb40fa2383c94aa5))


### Miscellaneous Chores

* **release:** test release ([#7759](https://github.com/werf/werf/issues/7759)) ([c4d8079](https://github.com/werf/werf/commit/c4d80799894e5ac8f2ac6a89f99f54221bc7a3b1))

## [3.0.2](https://github.com/werf/werf/compare/v3.0.1...v3.0.2) (2026-07-30)


### Bug Fixes

* **build:** assign per-image build-log progress index by real start order ([#7703](https://github.com/werf/werf/issues/7703)) ([7420f5f](https://github.com/werf/werf/commit/7420f5f5adee048916eb753dcd5e01d6b352e61e))

## [3.0.1](https://github.com/werf/werf/compare/v3.0.0-alpha.2...v3.0.1) (2026-07-29)


### Bug Fixes

* **build, stapel, import:** build rsync without lchmod support ([#7695](https://github.com/werf/werf/issues/7695)) ([f55c669](https://github.com/werf/werf/commit/f55c66913460d4cb6b9a8735fc75d5bb8ff7a9c8))


### Miscellaneous Chores

* release 3.0.1 ([7c8239e](https://github.com/werf/werf/commit/7c8239ebbd4d99a81a0ae3343413d1989abfb0a9))

## [3.0.0-alpha.2](https://github.com/werf/werf/compare/v2.75.2...v3.0.0-alpha.2) (2026-07-29)


### Features

* **deploy:** restore --no-create-namespace and --lookup-resources ([bb5f9e5](https://github.com/werf/werf/commit/bb5f9e54f5194e6fec97e083033093a3e187ca4b))


### Bug Fixes

* address v3 branch review findings from [#7686](https://github.com/werf/werf/issues/7686) ([#7692](https://github.com/werf/werf/issues/7692)) ([c34fedd](https://github.com/werf/werf/commit/c34feddad62a005d61a633809be254d32bb5b99b))
* **build, dockerfile:** treat COPY --parents destination as a directory ([#7693](https://github.com/werf/werf/issues/7693)) ([05faec0](https://github.com/werf/werf/commit/05faec0564d9b18d38d162dc673ebce91709ba6e))
* **build:** honor COPY --parents in staged Dockerfile build ([#7690](https://github.com/werf/werf/issues/7690)) ([c6e5df4](https://github.com/werf/werf/commit/c6e5df4cceabe16b9ba17dc332d6fad1f2096999))
* **build:** honor COPY/ADD --exclude in staged Dockerfile build ([#7691](https://github.com/werf/werf/issues/7691)) ([1ee4aac](https://github.com/werf/werf/commit/1ee4aac13a9af6ad04eba684cef7fd9699ffa2e6))


### Miscellaneous Chores

* release 3.0.0-alpha.2 ([776c33d](https://github.com/werf/werf/commit/776c33d3d553595bca413ce0ee03cd6a5d9035c1))

## [3.0.0-alpha.1](https://github.com/werf/werf/compare/v2.73.2...v3.0.0-alpha.1) (2026-07-10)


### Features

* **build, cleanup:** add --meta-repo to decouple metadata storage ([#7637](https://github.com/werf/werf/issues/7637)) ([8dd7118](https://github.com/werf/werf/commit/8dd7118037e0436b0f36364de02518dd926d6d17))
* **build, stapel:** deprecate fromImage and import.image directives ([#7628](https://github.com/werf/werf/issues/7628)) ([b064fd5](https://github.com/werf/werf/commit/b064fd52edbef1c7e18620e78cb9c76b30cd6b10))
* **build:** introduce content-anchor stage ([#7638](https://github.com/werf/werf/issues/7638)) ([5f269f2](https://github.com/werf/werf/commit/5f269f20a9b6a570099406c118924fd9e9fc6f59))
* **ci-env:** auto-detect DOCKER_AUTH_CONFIG to enable --use-docker-auth-config ([#7624](https://github.com/werf/werf/issues/7624)) ([7754d6b](https://github.com/werf/werf/commit/7754d6bc68ad19add5e5ff02a3cb02c10f21d024))
* **config list:** default --final-images-only=true, drop --images-only alias ([#7647](https://github.com/werf/werf/issues/7647)) ([edff312](https://github.com/werf/werf/commit/edff312515389d3d0cc9080223043e0b02babbad))
* **config:** add dependencies.from directive, deprecate dependencies.image ([#7639](https://github.com/werf/werf/issues/7639)) ([5051502](https://github.com/werf/werf/commit/505150210bb98879ebbac0892dc8d5ebc3f81e57))
* **deploy:** add `werf.io/resource-policy` annotation ([#7613](https://github.com/werf/werf/issues/7613)) ([72ae0f2](https://github.com/werf/werf/commit/72ae0f24ea745a81c61656d1c25df8dace2538f6))
* **deploy:** enable specific images params by default for converge/plan ([#7616](https://github.com/werf/werf/issues/7616)) ([21e7159](https://github.com/werf/werf/commit/21e71590ea0644e8e9c10573aab0fd4fbc468b69))
* **deploy:** expose `.global.env` only if `WERF_LEGACY_VALUES_GLOBAL_ENV` is set ([#7636](https://github.com/werf/werf/issues/7636)) ([41376d3](https://github.com/werf/werf/commit/41376d38a03eec81696c168536c458d63dafdd2d))
* **deploy:** make container backend optional for converge and render ([#7625](https://github.com/werf/werf/issues/7625)) ([1230498](https://github.com/werf/werf/commit/1230498c6dfb16e8c46c76d0d0c8329d80873013))
* **stapel, build:** embed stapel ([#7601](https://github.com/werf/werf/issues/7601)) ([82a8117](https://github.com/werf/werf/commit/82a81175bf678e749b145f2f5e468c3ee018ef75))


### Bug Fixes

* **build, stapel, git:** remove git commit ancestry check on stage reuse ([#7615](https://github.com/werf/werf/issues/7615)) ([70ee990](https://github.com/werf/werf/commit/70ee990c7d5b9eb02c806de4c1538d6d588c99d8))
* **build:** avoid splitting UTF-8 runes across parallel worker log reads ([#7632](https://github.com/werf/werf/issues/7632)) ([14fddc6](https://github.com/werf/werf/commit/14fddc6015ca8b53eeff0f3faf21c4d2433a14dc))
* **build:** default --final-images-only to true for consistency ([#7618](https://github.com/werf/werf/issues/7618)) ([52f4033](https://github.com/werf/werf/commit/52f403390e65cdaf24bd66a876235e79d97decd8))
* **build:** error on ambiguous trailing slash in export/import to: path ([#7627](https://github.com/werf/werf/issues/7627)) ([0f7a4e3](https://github.com/werf/werf/commit/0f7a4e35ad0c0b27941f19d45d52911eb794677a))
* **build:** hold back split UTF-8 across worker reads after half-close ([eda346e](https://github.com/werf/werf/commit/eda346e7f948accd8bd45560acf2ccceb2537cf2))
* **build:** re-check content-tag before ShouldBeBuiltMode error ([cbd8e77](https://github.com/werf/werf/commit/cbd8e77dc193a5a1557b868dde6f9239361d8f5f))
* **build:** send valid empty tar for docker from:scratch import ([#7609](https://github.com/werf/werf/issues/7609)) ([1c59585](https://github.com/werf/werf/commit/1c5958506a960167c76dede2cfa88ed130db1d12))
* **build:** serialize content-tag resolve+publish under digest mutex ([9d307ee](https://github.com/werf/werf/commit/9d307eec623262e6e18658b55c60cc120c0a60f1))
* **build:** stop leaking build-time env vars into final image config ([#7620](https://github.com/werf/werf/issues/7620)) ([02a8cb0](https://github.com/werf/werf/commit/02a8cb0be93641b832f782c12fb6a01aa91c3abe))
* **build:** use jsonmessage API to parse image load response ([5fe36bc](https://github.com/werf/werf/commit/5fe36bc78ecabe6b58439eca16ca9f82869264d1))
* **bundle:** update .Values.global.werf.images during bundle copy ([#7600](https://github.com/werf/werf/issues/7600)) ([cf2fb96](https://github.com/werf/werf/commit/cf2fb96d2de01c13d8c733589cb02262eb9521b1))
* **deploy:** `werf.io/resource-policy` should only respect skip-delete from live ([#7623](https://github.com/werf/werf/issues/7623)) ([f261028](https://github.com/werf/werf/commit/f261028ca4b92b48ef9e26c353c0adade1e331ea))
* **deploy:** use chartcommon.File after main merge in copy_test ([473c07e](https://github.com/werf/werf/commit/473c07ea807565559137081767341c3c5d3d43d9))
* **host-cleanup:** GC stale host lock files on cleanup ([#7619](https://github.com/werf/werf/issues/7619)) ([1c8eb88](https://github.com/werf/werf/commit/1c8eb885b6b1a941d24ca68f3981352e9063901b))
* **test, e2e:** pull image before local save/push in loadLocalImage helper ([3e420f7](https://github.com/werf/werf/commit/3e420f72e5d43fb9a48f22532c2ab04726b46ae5))
* **test:** update e2e fixtures for v3 external image tag and trailing-slash rules ([9ef0cc4](https://github.com/werf/werf/commit/9ef0cc4a106b535cf6634a2c47947a56ae68ff45))


### Miscellaneous Chores

* release 3.0.0-alpha.1 ([5753958](https://github.com/werf/werf/commit/5753958be672640442d6d193c2d6365f07c9c603))

## [2.75.3-dk.1](https://github.com/deckhouse/delivery-kit/compare/v2.75.2-dk.1...v2.75.3-dk.1) (2026-07-29)


### Bug Fixes

* **ci:** force -dk increment via release-please CLI ([ad15030](https://github.com/deckhouse/delivery-kit/commit/ad150308d6f3d5ee151d016797fbfa5b835de578))
* **ci:** force -dk increment via release-please CLI ([b539916](https://github.com/deckhouse/delivery-kit/commit/b53991668d3d808d9c0d5f4c807ff2b0e41090ae))
* **host-cleanup:** stop wiping other werf versions' live git cache ([#7699](https://github.com/deckhouse/delivery-kit/issues/7699)) ([3e43c28](https://github.com/deckhouse/delivery-kit/commit/3e43c28ba80c0cc2d8ea1f52e5e2fb314977b6f1))


### Miscellaneous Chores

* force release 2.75.3-dk.1 ([c88fd8e](https://github.com/deckhouse/delivery-kit/commit/c88fd8e699a6eee3869c153821797add90a06657))

## [2.75.2-dk.1](https://github.com/deckhouse/delivery-kit/compare/v2.75.1-dk...v2.75.2-dk.1) (2026-07-28)


### Features

* **build, oci:** add commands to manage oci artifacts ([#162](https://github.com/deckhouse/delivery-kit/issues/162)) ([61e83fb](https://github.com/deckhouse/delivery-kit/commit/61e83fba05b23ce54527498ce5cb316d57cbfca2))
* **deploy:** add --lookup-resources flag for offline lookup in render/lint commands ([#7666](https://github.com/deckhouse/delivery-kit/issues/7666)) ([3b0f422](https://github.com/deckhouse/delivery-kit/commit/3b0f42205264a8aea563f881c9b9378aeba1d351))
* **sbom:** add JavaScript package ecosystem types (npm, yarn, pnpm) ([c70ec68](https://github.com/deckhouse/delivery-kit/commit/c70ec687e5e9b5c2e0966479185801162fb5e336))
* **sbom:** don't enforce pm determnism ([c22beb5](https://github.com/deckhouse/delivery-kit/commit/c22beb5ac70ec3967909ba455bfb7b23617c358b))


### Bug Fixes

* **build, oci:** hide OCI attestation commands from help output ([5a17940](https://github.com/deckhouse/delivery-kit/commit/5a179403d01fb078ebbedf7535875eafb355167e))
* **build:** drop full images report JSON dumps from debug log ([a4e4c50](https://github.com/deckhouse/delivery-kit/commit/a4e4c506ec4fa7b8ee5c72037cb5db2cb69a655f))
* **ci:** detect Release-As footer without a pipeline ([93694e2](https://github.com/deckhouse/delivery-kit/commit/93694e2268d9d5ffc2f4d9883503a646bbf161b3))
* **config:** use stapel coreutils in pm snapshot command ([a39429c](https://github.com/deckhouse/delivery-kit/commit/a39429c41524945ee7fffa6c938a3d7f23d497a1))
* **deploy:** create release namespace under strict RBAC, `--no-create-namespace` flag ([#7668](https://github.com/deckhouse/delivery-kit/issues/7668)) ([5c9d62a](https://github.com/deckhouse/delivery-kit/commit/5c9d62a0c8b73fd13e861136961537a5470679c1))
* **deploy:** don't block deploy when Helm managed fields reconstruction hits incompatible historical manifest ([#7673](https://github.com/deckhouse/delivery-kit/issues/7673)) ([c7f3677](https://github.com/deckhouse/delivery-kit/commit/c7f3677b80ddf34b98182ff00a7a622994dbf05c))
* **sbom:** batch PURL resolver errors across image sets ([#196](https://github.com/deckhouse/delivery-kit/issues/196)) ([b514e96](https://github.com/deckhouse/delivery-kit/commit/b514e968c0e6d2c0213124e2b9450e19489ed6e7))
* **sbom:** read pm files from image without executing coreutils ([252d0c1](https://github.com/deckhouse/delivery-kit/commit/252d0c1a4c41eda79d4217ac4d1f24770bba9d3f))
* **sbom:** reduce PURL resolver retry duration to 10s and HTTP timeout ([11cea67](https://github.com/deckhouse/delivery-kit/commit/11cea67e55a5b07399a115f1150e8fe54b58b156))


### Miscellaneous Chores

* force release 2.75.2-dk.1 ([720962d](https://github.com/deckhouse/delivery-kit/commit/720962d3d612bb27a899ae0169caedf981a80720))
* release 2.75.2 ([def3a23](https://github.com/deckhouse/delivery-kit/commit/def3a23e1e672485a3e8aa8bd37e5efc3963ab81))

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

---
title: VEX
permalink: usage/build/vex.html
---

Сканер уязвимостей сообщает о каждой CVE, которую может сопоставить с пакетами в образе, — в том числе о тех, что для этого образа не имеют значения: уязвимая функция никогда не вызывается, затронутая возможность выключена конфигурацией, или исправление бэкпортировано под той же версией пакета. [VEX](https://openvex.dev/) (Vulnerability Exploitability eXchange) — стандартный способ зафиксировать такие вердикты, чтобы сканеры и инструменты аудита перестали их поднимать.

werf позволяет держать VEX-документ рядом с образом, который он описывает: объявите его в `werf.yaml`, и `werf build` опубликует его в container registry как аттестацию образа — подписанную тем же ключом, что и [SBOM]({{ "/usage/build/sbom.html" | true_relative_url }}), если подпись включена. Любой, у кого есть образ, может получить вердикты, проверить, кто их подписал, и передать их своему сканеру.

werf не пишет VEX-утверждения за вас: решение о том, что CVE не применима, — это суждение о безопасности, которое принимает сопровождающий образа, а сам документ ведётся в Git, как и остальная конфигурация.

## Быстрый старт

1. Напишите документ [OpenVEX](https://github.com/openvex/spec), например `vex/app.openvex.json`. Продукт — это образ так, как его видит сканер: репозиторий, куда он опубликован, а не имя `image:` из `werf.yaml` (подробности — в разделе [Использование вердиктов при сканировании](#использование-вердиктов-при-сканировании)):

   ```json
   {
     "@context": "https://openvex.dev/ns/v0.2.0",
     "@id": "https://example.com/vex/app-2024-06-01",
     "author": "Security team <security@example.com>",
     "timestamp": "2024-06-01T00:00:00Z",
     "version": 1,
     "statements": [
       {
         "vulnerability": {"name": "CVE-2024-12345"},
         "products": [{"@id": "pkg:oci/project?repository_url=registry.example.com/project"}],
         "status": "not_affected",
         "justification": "vulnerable_code_not_in_execute_path",
         "impact_statement": "The vulnerable function is never called in this build."
       }
     ]
   }
   ```

2. Укажите его в `werf.yaml` для образа — путь относительно директории проекта, директива одинаково работает для Dockerfile- и Stapel-образов — и закоммитьте оба файла: гитерминизм читает их из коммита:

   ```yaml
   image: app
   dockerfile: Dockerfile
   vex: vex/app.openvex.json
   ```

   ```shell
   git add werf.yaml vex/app.openvex.json && git commit -m "Add VEX for app"
   ```

3. Соберите с registry, присвоив образу тег, по которому к нему можно будет обращаться дальше. Если ваши сборки подписывают SBOM или манифесты, передавайте тот же `--sign-key` — VEX-документ подписывается им же:

   ```shell
   werf build --repo registry.example.com/project --add-custom-tag '%image%-1.2.3' [--sign-key KEY]
   ```

   Лог подтверждает публикацию для каждого образа с документом:

   ```
   image app: Published VEX artifact
   ```

   Без `--sign-key` документ публикуется **без подписи**: любой, у кого есть права на push в репозиторий, может его подменить. Потребители, которым нужно доверять вердиктам, проверяют подпись через `werf attest verify`, а не `get` ниже; см. [Доверие к вердиктам](#доверие-к-вердиктам).

4. Убедитесь, что документ прикреплён к образу:

   ```shell
   werf attest get --type openvex --repo registry.example.com/project --tag app-1.2.3
   ```

   Команда печатает документ, который вы закоммитили.

## Работа с VEX день за днём

### Сканер сообщает о CVE, которая не применима

Убедитесь в вердикте, затем добавьте утверждение в документ образа: идентификатор CVE ровно так, как его сообщает сканер (`vulnerability.name`), образ в качестве продукта, `status: not_affected` с одним из пяти обоснований OpenVEX — `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist` (их смысл — в [спецификации](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)) — и `impact_statement`, объясняющий ход мысли тому, кто придёт после вас. Если речь только об определённом пакете, сузьте утверждение через `subcomponents` (PURL пакета); утверждение без `subcomponents` относится к каждому вхождению этой CVE в образе.

CVE, которая в вашей сборке действительно исправлена — например, бэкпортированным патчем, — записывается со `status: fixed`. Сканеры трактуют и `not_affected`, и `fixed` как «не сообщать». Чтобы отозвать вердикт, смените `status` утверждения на `affected` (или удалите утверждение) — сканер снова начнёт сообщать о CVE.

При изменении документа увеличивайте `version` и обновляйте `timestamp`: werf этого не требует (он переопубликовывает при любом изменении содержимого файла), но потребители OpenVEX по ним упорядочивают документы об одном продукте. `@id` документа — идентификатор, а не URL, который должен открываться: подойдёт любой IRI, уникальный в вашей организации.

Закоммитьте документ и снова запустите `werf build` с теми же флагами, что и раньше. **Образ не пересобирается**: директива `vex` и содержимое документа не участвуют в дайджестах стадий, поэтому сборка лишь переопубликовывает аттестацию для того же дайджеста образа. Держите документ вне путей, попадающих в образ: VEX-файл внутри `git`-маппинга Stapel-образа или копируемый Dockerfile-инструкцией `COPY` — обычное содержимое образа, и его правка пересобирает образ как любой другой файл.

### Использование вердиктов при сканировании

Получите документ из registry и передайте его сканеру. С [Trivy](https://trivy.dev/latest/docs/supply-chain/vex/file/):

```shell
werf attest get --type openvex --repo registry.example.com/project --tag app-1.2.3 > app.openvex.json
trivy image --vex app.openvex.json registry.example.com/project:app-1.2.3
```

Находки, покрытые утверждением `not_affected` или `fixed`, исключаются из отчёта; `--show-suppressed` показывает их вместе с утверждением, которое их подавило.

Утверждение применяется, когда совпадают и идентификатор уязвимости, и продукт. Для образа Trivy ожидает продукт в виде PURL `pkg:oci`: репозиторий, из которого сканер забирает образ, идёт в `repository_url` — `--final-repo`, если вы его используете (именно он сканируется и деплоится), иначе `--repo`, — его последний сегмент пути — имя, а дайджест образа необязателен:

```
pkg:oci/project?repository_url=registry.example.com/project                  # все образы репозитория
pkg:oci/project@sha256:<digest>?repository_url=registry.example.com/project  # один дайджест образа
```

Обратите внимание: имя берётся из репозитория, а не из `image:` в `werf.yaml`, а werf публикует все образы проекта в один репозиторий. Продукт без дайджеста поэтому покрывает каждый образ проекта — это нормально, пока у каждого образа свой документ со своими утверждениями: сканер видит только тот документ, который вы ему передали. Чтобы привязать утверждение к одному образу независимо от того, какой документ используется, зафиксируйте дайджест: после сборки он есть в [отчёте о сборке]({{ "/usage/build/process.html#отчёт-по-сборке" | true_relative_url }}) (`werf build --save-build-report`, поле `Images.<name>.DockerImageDigest`), для мультиплатформенного образа это дайджест индекса. Поскольку дайджест меняется при каждой пересборке образа, фиксацию лучше оставить для вердиктов, относящихся к одной конкретной сборке.

Чтобы ограничить утверждение одним пакетом, добавьте его PURL как subcomponent продукта — возьмите его из JSON-отчёта Trivy (`trivy image -f json …`, поле `PkgIdentifier.PURL` у находки):

```json
"products": [{
  "@id": "pkg:oci/project?repository_url=registry.example.com/project",
  "subcomponents": [{"@id": "pkg:deb/debian/openssl"}]
}]
```

Если CVE продолжает выводиться после применения документа, сверьте с JSON-отчётом три вещи: идентификатор уязвимости (`VulnerabilityID`), PURL продукта (репозиторий и, если вы его указали, дайджест сканируемого образа) и PURL пакета в `subcomponents`. Правила сопоставления описаны на страницах Trivy [Local VEX files](https://trivy.dev/latest/docs/supply-chain/vex/file/) и [OCI VEX](https://trivy.dev/latest/docs/supply-chain/vex/oci/).

### Доверие к вердиктам

Если сборка была подписана (`--sign-key`), аттестация несёт подпись, и потребитель может отвергать неподписанные или подменённые вердикты:

```shell
werf attest verify --type openvex --key vex-signer.pub \
  --repo registry.example.com/project --tag app-1.2.3 > app.openvex.json
```

`werf attest verify` печатает документ только после того, как подпись сошлась с одним из переданных публичных ключей (`--key` можно повторять); неподписанная или неверно подписанная аттестация завершает команду ошибкой без вывода. `werf attest get` печатает документ без проверки.

Потребитель без werf может проверить ту же аттестацию стандартным [cosign](https://github.com/sigstore/cosign) (v2.5 и новее), полностью офлайн: аттестация — стандартный Sigstore bundle, а подписи werf по ключу не записываются в журнал прозрачности, отсюда trusted root без сервисов и `--insecure-ignore-tlog`:

```shell
cosign trusted-root create --out trusted-root.json
cosign verify-attestation --new-bundle-format --trusted-root trusted-root.json --insecure-ignore-tlog=true \
  --key vex-signer.pub --type openvex registry.example.com/project@sha256:<digest>
```

Для мультиплатформенного образа `<digest>` — дайджест индекса образа.

Подпись использует те же флаги и ключи, что и [подписание SBOM]({{ "/usage/build/sbom.html#подписание-sbom" | true_relative_url }}): `--sign-key` / `WERF_SIGN_KEY` (PEM-файл, PEM в base64 или `hashivault://[KEY]`), опционально `--sign-cert` и `--sign-intermediates`. Без `--sign-key` документ публикуется неподписанным — это не ошибка. Включение подписи, ротация ключа или отказ от подписи переопубликовывают аттестацию при следующей сборке без пересборки образа.

### Что прикреплено к образу

```shell
werf attest ls --repo registry.example.com/project --tag app-1.2.3
```

показывает все аттестации образа — SBOM по платформам и VEX-документ — с их predicate type, дайджестом и признаком подписи:

```
PLATFORM     PREDICATE TYPE             DIGEST                  SIGNED
linux/amd64  https://cyclonedx.org/bom  sha256:3f1c9a0b2d4e...  yes
linux/arm64  https://cyclonedx.org/bom  sha256:8e7d6c5b4a39...  yes
index        https://openvex.dev/ns     sha256:a1b2c3d4e5f6...  yes
```

Для мультиплатформенного образа VEX-документ выводится под платформой `index`, потому что описывает образ целиком и прикреплён к индексу образа, а не к манифесту платформы; `--platform OS/ARCH` показывает только аттестации этой платформы.

## Чего ожидать

- **Нужен registry.** Аттестация живёт только в container registry. С локальным хранилищем стадий (без `--repo`) шаг VEX молча пропускается и ничего не публикуется.
- **Куда она попадает.** Аттестация публикуется в `--repo` и копируется в `--final-repo` вместе с образом. Для одноплатформенного образа — также в `--cache-repo`; VEX мультиплатформенного образа прикреплён к индексу образа, которого в кеширующих репозиториях не бывает, поэтому туда не копируется. `--secondary-repo` доступен только для чтения. Копирование выполняется при каждой сборке, так что репозиторий, где образ лежит без аттестаций, дополнится следующим запуском.
- **У мультиплатформенного образа один документ.** В отличие от SBOM, который создаётся на каждую платформу, VEX-аттестация одна и прикреплена к индексу образа. `werf attest get` и `werf attest verify` принимают ссылку на индекс; `--platform` для `--type openvex` на индексе отклоняется.
- **У ранее собранных образов его нет.** VEX-аттестация есть у образов, собранных после добавления директивы `vex`; до следующего `werf build --repo` старые образы документа не несут. Верно и обратное: удаление директивы `vex` прекращает публикацию, но не открепляет уже лежащее в registry — дайджест образа, получивший документ, сохраняет его. Чтобы отозвать вердикты у образа, который продолжает использоваться, опубликуйте документ, в утверждениях которого стоит `affected`.
- **Документ не менялся, образ не менялся → ничего не происходит.** Сборка сообщает `VEX artifact is up to date — skipping publish`. Переопубликацию вызывает изменение документа, дайджеста образа или ключа подписи.
- **`--check-built-images` ничего не публикует**, включая VEX; он только проверяет, что образы существуют. `--require-built-images` (`-Z`) — не режим проверки: он публикует ранее собранные образы и выполняет шаг VEX как обычная сборка.
- **Прикреплённые вручную аттестации имеют приоритет.** Аттестация, прикреплённая командой `werf attest sign`, хранится отдельно от опубликованной сборкой: сборка её не заменяет, и пока существуют обе, `werf attest get` и `werf attest verify` возвращают прикреплённую вручную. Правка документа в Git и пересборка обновляют только сборочную аттестацию — если у образа есть прикреплённый вручную VEX, обновите и его через `werf attest sign`, либо не прикрепляйте VEX вручную к образам, у которых он есть из сборки. Команды для открепления аттестации нет; практический путь назад — пересобрать образ под новым дайджестом, у которого прикреплённых вручную аттестаций ещё нет.

### Ошибки валидации

Документ читается и проверяется при разборе `werf.yaml`, поэтому некорректный документ ломает любую команду werf, читающую конфигурацию, а не только `werf build`. werf требует, чтобы файл существовал, был JSON и нёс контекст OpenVEX в точности — `"@context": "https://openvex.dev/ns/v0.2.0"`; сами утверждения не проверяются.

```
`vex` directive must specify a VEX document path, use `vex: PATH` or `vex:
  document: PATH`
unable to read VEX file "vex/app.openvex.json": ...
invalid VEX document "vex/app.openvex.json": VEX document is not valid JSON
invalid VEX document "vex/app.openvex.json": VEX document has unexpected @context "...", expected "https://openvex.dev/ns/v0.2.0"
```

### Гитерминизм

Как и сам `werf.yaml`, VEX-документ читается из текущего коммита: незакоммиченный или неотслеживаемый документ роняет сборку обычной для гитерминизма ошибкой, а `--dev` работает как для любого другого файла. Чтобы постоянно разрешить чтение определённых документов из рабочей директории, перечислите их в `werf-giterminism.yaml`:

```yaml
giterminismConfigVersion: 1
config:
  vex:
    allowUncommitted:
      - vex/*.openvex.json
```

О последствиях см. раздел [о гитерминизме]({{ "/usage/project_configuration/giterminism.html#vex" | true_relative_url }}).

## Справочник

### `werf.yaml`

```yaml
vex: PATH
# или
vex:
  document: PATH
```

Обе формы эквивалентны. `PATH` задаётся относительно директории проекта. Директива принимается для Dockerfile- и Stapel-образов.

### Формат хранения

Аттестация хранится как OCI-артефакт, subject которого указывает на манифест (или индекс) образа, так же как и [SBOM]({{ "/usage/build/sbom.html#как-хранится-sbom" | true_relative_url }}): werf поддерживает индекс на основе тегов, работающий с любым registry, и дополнительно выставляет поле OCI `subject` для инструментов, понимающих OCI referrers API.

Документ OpenVEX упаковывается в [in-toto](https://in-toto.io/) statement, а затем в [DSSE](https://github.com/secure-systems-lab/dsse) envelope:

| | Неподписанная сборка | Подписанная сборка (`--sign-key`) |
|---|---|---|
| Media type слоя | `application/vnd.dsse.envelope.v1+json` | `application/vnd.dev.sigstore.bundle.v0.3+json` — Sigstore bundle с подписанным DSSE envelope и подсказкой о публичном ключе |
| Predicate type in-toto | `https://openvex.dev/ns/v0.2.0` | `https://openvex.dev/ns` |

Подписанная форма использует URI predicate без версии, потому что именно в него cosign разрешает тип `openvex`, — так подписанная аттестация проверяется и стандартным cosign. Оба URI обозначают один вид аттестации, и `--type openvex` находит любой из них. На образ хранится ровно одна опубликованная сборкой VEX-аттестация: подписанная заменяет неподписанную и наоборот. Свои аттестации werf узнаёт по аннотации `io.werf.checksum`, вычисляемой из содержимого документа, дайджеста образа, отпечатка ключа подписи и версии формата артефакта, — именно она решает, переопубликует ли сборка аттестацию.

### `werf attest`

`--repo` обязателен для каждой подкоманды; образ задаётся через `--tag` или `--digest` (взаимоисключающие), а `--image` сужает поиск до одного имени образа, если несколько образов делят один дайджест. `--type` принимает `openvex`, `cyclonedx`, `slsaprovenance`, `slsaprovenance1`, `spdxjson` или полный URI predicate.

- [`werf attest get`]({{ "/reference/cli/werf_attest_get.html" | true_relative_url }}) — напечатать документ без проверки подписи.
- [`werf attest verify`]({{ "/reference/cli/werf_attest_verify.html" | true_relative_url }}) — проверить подпись ключом `--key` (можно повторять), затем напечатать документ.
- [`werf attest ls`]({{ "/reference/cli/werf_attest_ls.html" | true_relative_url }}) — перечислить аттестации образа.
- [`werf attest sign`]({{ "/reference/cli/werf_attest_sign.html" | true_relative_url }}) — подписать произвольный файл predicate (`--predicate`, `--type`) обычным PEM-ключом `--sign-key` и прикрепить его к образу.

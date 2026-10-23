---
title: Подписание файлов внутри образа
permalink: usage/build/signing_files.html
---

Директива `sign` Stapel-образа подписывает файлы, которые производит образ, — архив релиза, пакет конфигурации или политик, прошивку — и кладёт рядом с каждым отсоединённую подпись `<path>.p7s`. Приватный ключ не попадает в сборочный контейнер: werf читает файл из образа, подписывает его на сборочном хосте и добавляет подпись новым слоем.

Директива нужна, когда:

- образ поставляет файл, подпись которого проверяет потребитель, например агент, который загружает пакет политик, только если его подпись выстраивается в цепочку до доверенного CA;
- ключ подписи хранится в KMS (Vault Transit), а сборочные контейнеры не должны получать доступ к нему;
- включён [SBOM]({{ "/usage/build/sbom.html" | true_relative_url }}), поэтому shell-стадии выполняются без сети и сами до KMS не доберутся.

Полный список опций — в [справочном разделе]({{ "/usage/build/stapel/imports.html#подписание-файлов-внутри-образа" | true_relative_url }}). На этой странице — настройка подписания от начала до конца.

## Как это работает

1. В `werf.yaml` перечисляются подписываемые файлы и для каждого — момент сборки, когда он готов.
2. В этот момент werf добавляет стадию подписания. Стадия читает файл из собранного к этому моменту образа, подписывает его ключом из командной строки и кладёт рядом `<path>.p7s`.
3. Контейнер стадии всегда запускается с `network: none`, и команды образа в нём не выполняются.
4. Последующие стадии и образы, которые импортируют из этого, видят файл вместе с подписью.

Подпись — отсоединённый PKCS#7 (CMS) `SignedData`: SHA-256, RSASSA-PKCS1-v1_5, без аутентифицированных атрибутов, со встроенным сертификатом подписанта. Именно такую форму производит `systemd-keyutil pkcs7`, и её проверяет OpenSSL или любая другая реализация CMS.

## Что понадобится

- **RSA-ключ.** Ключ Vault Transit RSA-типа или локальный файл ключа. Ключи других типов отвергаются. Локальный файл ключа должен быть зашифрованным PEM с пустым паролем (`ENCRYPTED DELIVERY-KIT PRIVATE KEY`); обычный ключ OpenSSL не принимается — ошибка `decrypt: ...`. Сконвертировать существующий RSA-ключ можно, например, через cosign:

  ```shell
  COSIGN_PASSWORD="" cosign import-key-pair --key rsa.pem --output-key-prefix files-signing
  sed 's/ENCRYPTED SIGSTORE PRIVATE KEY/ENCRYPTED DELIVERY-KIT PRIVATE KEY/' files-signing.key > files-signing.dk.key
  ```
- **Сертификат этого ключа** (leaf, PEM). werf не запрашивает его ни из KMS, ни из PKI: пайплайн получает его сам и передаёт путём или в base64. Сертификат публичный, его можно хранить и в репозитории.
- **Для Vault Transit — роль с доступом к ключу.** werf подписывает через `<mount>/sign/<key>/sha2-256` и читает открытый ключ из `<mount>/keys/<key>`, чтобы сверить его с сертификатом, поэтому политике нужны оба права:

  ```hcl
  path "transit/sign/files-signing/sha2-256" {
    capabilities = ["update"]
  }

  path "transit/keys/files-signing" {
    capabilities = ["read"]
  }
  ```

## Шаг 1. Объявить файлы в `werf.yaml`

Добавьте список `sign` в образ, который производит файл:

```yaml
image: policies
from: alpine:3.20
git:
- add: /policies
  to: /src/policies
shell:
  install:
  - mkdir -p /out
  - tar -C /src/policies -czf /out/policies.tar.gz .
sign:
- path: /out/policies.tar.gz
```

Без `before` и `after` файл подписывается в конце образа, когда его файловая система уже собрана. В большинстве случаев это правильный выбор: подпись покрывает ровно то, что поставляет образ, и её получает каждый образ, импортирующий из этого.

Чтобы подписать на границе стадии, задайте `before` или `after` со значением `install` или `setup`:

| Запись | Файл подписывается | `.p7s` виден в |
|---|---|---|
| без `before`/`after` | в конце образа | образах, импортирующих из этого |
| `before: install` | перед `install` | `install`, `beforeSetup`, `setup` |
| `after: install` | после `install` | `beforeSetup`, `setup` |
| `before: setup` | перед `setup` | `setup` |
| `after: setup` | после `setup` | образах, импортирующих из этого |

Правила:

- `path` — абсолютный путь к обычному файлу, который существует в образе в этот момент. Директория, относительный путь или `/` — ошибка.
- Каждый `path` встречается в списке один раз.
- `before` и `after` одновременно задавать нельзя.
- Запись не может подписывать `.p7s` другой записи на той же позиции. Чтобы подписать подпись, задайте второй записи более позднюю позицию.
- Директива есть только у Stapel-образов.

## Шаг 2 (необязательный). Проверить подпись во время сборки

Подпишите на границе стадии и проверьте подпись в следующей стадии, где ошибку легко разобрать:

```yaml
sign:
- path: /out/policies.tar.gz
  after: install
shell:
  beforeInstall:
  - apk add --no-cache openssl
  install:
  - mkdir -p /out
  - tar -C /src/policies -czf /out/policies.tar.gz .
  setup:
  - openssl smime -verify -inform der -in /out/policies.tar.gz.p7s -content /out/policies.tar.gz -noverify -out /dev/null
```

`-noverify` проверяет подпись над содержимым, но не цепочку сертификатов. Чтобы проверить и цепочку, положите сертификат CA в образ и передайте его через `-CAfile` вместо `-noverify`.

## Шаг 3. Передать подпись в другие образы

Образ, который импортирует подписанный файл, должен импортировать и его подпись:

```yaml
image: agent
from: alpine:3.20
import:
- image: policies
  add: /out
  to: /etc/agent
  after: install
  includePaths:
  - policies.tar.gz
  - policies.tar.gz.p7s
```

При позиции по умолчанию подпись уже есть в импортируемом образе. С `before`/`after` файл и подпись есть в образе, как только эта позиция пройдена.

## Шаг 4. Передать ключ и сертификат

Ключ и сертификат никогда не попадают в `werf.yaml`. Они передаются через командную строку или окружение, отдельно от `--sign-key`/`--sign-cert`, которыми подписываются манифесты и SBOM.

С ключом в PEM-файле:

```shell
export WERF_SIGN_BUILD_FILE_KEY="$PWD/files-signing.dk.key"
export WERF_SIGN_BUILD_FILE_CERT="$PWD/files-signing.pem"
werf build --repo registry.example.com/project
```

С ключом Vault Transit и входом по JWT, например из GitLab CI:

```yaml
build:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  variables:
    WERF_SIGN_BUILD_FILE_KEY: hashivault://files-signing
    WERF_SIGN_BUILD_FILE_CERT: ci/files-signing.pem
    WERF_SIGN_BUILD_FILE_VAULT_ADDR: https://vault.example.com
    WERF_SIGN_BUILD_FILE_VAULT_TRANSIT_PATH: transit
    WERF_SIGN_BUILD_FILE_VAULT_AUTH_PATH: gitlab
    WERF_SIGN_BUILD_FILE_VAULT_AUTH_ROLE: files-signer
  script:
  - export WERF_SIGN_BUILD_FILE_VAULT_AUTH_JWT="$VAULT_ID_TOKEN"
  - werf build --repo "$WERF_REPO"
```

Если сертификат выпускает Vault PKI, получите его до сборки, например `vault read -field=certificate pki/cert/<serial> > ci/files-signing.pem`.

Как сочетаются опции Vault:

- `--sign-build-file-vault-addr` и `--sign-build-file-vault-transit-path` по отдельности подхватывают `VAULT_ADDR` и `TRANSIT_SECRET_ENGINE_PATH`, если не заданы.
- Аутентификация берётся целиком. С `--sign-build-file-vault-auth-jwt` werf входит с этим JWT, ролью из `--sign-build-file-vault-auth-role` и mount из `--sign-build-file-vault-auth-path` (`jwt`, если не задан). Каждое из значений можно задать флагом или своей переменной `WERF_SIGN_BUILD_FILE_VAULT_AUTH_*`, но ни одно не подхватывается из аутентификации `--sign-key`.
- Без JWT werf входит так же, как `--sign-key`, — из окружения. Роль или mount без JWT — ошибка.

Все записи `sign` в одной сборке используют этого одного подписанта.

## Шаг 5. Запустить остальные команды

Сертификат участвует в дайджесте стадии подписания, а значит, и в теге образа. Он нужен каждой команде, которая вычисляет стадии образа с `sign`, — не только `build`, но и `converge`, `render`, `plan`, `run`, `compose`, `kube-run`, `export`, `bundle publish`, `lint`, `sbom get`, `stages copy`, `stage image` и `helm get-autogenerated-values`. Без него они падают до запуска стадий.

Приватный ключ нужен только там, где создаётся подпись, то есть где стадии подписания ещё нет в registry. Джобе деплоя, которая использует собранные ранее образы, достаточно сертификата:

```shell
export WERF_SIGN_BUILD_FILE_CERT="$PWD/files-signing.pem"
werf converge --require-built-images --repo registry.example.com/project
```

Если ни обрабатываемые образы, ни их зависимости не объявляют `sign`, не нужны ни сертификат, ни ключ.

Объявленная директива `sign` — требование образа: опции, которая собрала бы его без подписи, нет.

## Проверить результат

Достаньте файл и подпись из собранного образа и проверьте их на любом хосте:

```shell
crane export registry.example.com/project:<tag> - | tar -x out/policies.tar.gz out/policies.tar.gz.p7s
openssl smime -verify -inform der -in out/policies.tar.gz.p7s -content out/policies.tar.gz -CAfile ca.pem -purpose any -out /dev/null
```

`openssl asn1parse -inform der -in out/policies.tar.gz.p7s` показывает структуру: `sha256`, `rsaEncryption`, без подписанных атрибутов, один встроенный сертификат.

## Кэширование и ротация ключа

Стадия подписания кэшируется как любая другая. Её дайджест включает предыдущие стадии, подписываемые пути, позицию, сертификат и формат подписи:

- пересборка с теми же входными данными и тем же сертификатом переиспользует закэшированную подпись и не отправляет запросов на подписание. Если ключ передан, werf всё равно входит в Vault и читает открытый ключ при запуске, чтобы сверить его с сертификатом, поэтому в джобы, которые только используют собранные ранее образы, ключ не передавайте;
- другой сертификат пересобирает стадию подписания и все стадии после неё, поэтому образ получает новый тег;
- другой JWT, адрес Vault или ссылка на ключ тег не меняют.

Чтобы сменить ключ, передайте новый ключ вместе с его сертификатом. Сертификат, который не соответствует ключу, роняет сборку с ошибкой `public key in certificate does not match the provided public key`. Собранные ранее образы сохраняют старые подписи.

## Перенос подписания из сборочной стадии

Если сейчас образ подписывает файл в shell-стадии, входя в KMS из контейнера:

1. Замените команды входа и подписания записью `sign` для этого файла.
2. Перенесите проверку `.p7s` в стадию после позиции подписания (см. шаг 2): стадия, которая производит файл, его подпись больше не видит.
3. Уберите из образа секреты и монтирования, которые нужны были только для подписания (адрес KMS, токены, бинарник клиента KMS), а из `werf-giterminism.yaml` — соответствующие записи `secrets.allowEnvVariables` и `mount.allowFromPaths`, если они больше нигде не используются.
4. В CI передайте ключ, сертификат и опции Vault, как в шаге 4, а сертификат — каждой джобе, которая запускает werf с этим `werf.yaml`.

## Решение проблем

| Сообщение | Причина и что делать |
|---|---|
| `images <names> declare files to sign: specify the signing certificate with --sign-build-file-cert` | Команда обрабатывает образ с `sign`, а сертификата нет. Передайте `--sign-build-file-cert`/`WERF_SIGN_BUILD_FILE_CERT`, в том числе в джобы деплоя. |
| `image "<name>" declares files to sign and this stage is not built yet: specify the private key with --sign-build-file-key` | Стадию подписания нужно собрать, а ключа нет. Передайте ключ или используйте собранные ранее образы (`--require-built-images`). |
| `read <path> to sign from image "<name>": ...` | На позиции подписания файла нет. Перенесите запись на более позднюю позицию или уберите `before`/`after`. |
| `... is a directory, a regular file is required` или `not a regular file` | `path` указывает на директорию или специальный файл. Подписывайте обычный файл. |
| `public key in certificate does not match the provided public key` | Сертификат принадлежит другому ключу. Передайте сертификат этого ключа. |
| `signing certificate carries a ... public key, only RSA is supported for detached PKCS#7` | Ключ не RSA. Используйте RSA-ключ. |
| `the signing certificate does not verify the signature the key produced` | KMS подписал другим ключом или другой версией ключа, чем описывает сертификат. Проверьте имя ключа и сертификат. |
| `--sign-build-file-vault-auth-role and --sign-build-file-vault-auth-path qualify --sign-build-file-vault-auth-jwt: ...` | Роль или mount заданы без JWT. Передайте и JWT или уберите их. |
| `permission denied` от Vault на `<mount>/keys/<key>` или `<mount>/sign/<key>/sha2-256` | В политике роли нет `read` на ключ или `update` на подписание. См. раздел «Что понадобится». |
| `specify only one stage using ...`, `duplicated ... for sign!`, `conflicting ... for sign: ...` | Список `sign` нарушает одно из правил шага 1. |

## Ограничения

- Только Stapel-образы; позиции — границы `install` и `setup` и конец образа.
- Только RSA-ключи, SHA-256 и отсоединённая подпись PKCS#7 в отдельном `<path>.p7s`. Подпись, встроенная в сам файл, не создаётся.
- Один подписант на сборку для всех записей `sign`.
- Встраивается только сертификат подписанта; `--sign-build-file-intermediates` не участвует ни в подписи, ни в дайджесте.

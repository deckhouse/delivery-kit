---
name: werf-to-delivery-kit
description: Миграция сборочных конфигов модуля с werf на delivery-kit v3 (dk3, от v3.4.0). Переписывает werf.yaml и все images/*/werf.inc.yaml на новый синтаксис — from вместо fromImage, включение SBOM (cyclonedx@1.6), замена сетевых shell-инструкций (git clone, pm install, go mod download, npm install -g, cosign attest и т.п.) на директивы git, packages (в т.ч. manager и %secret% в env) и vex; перевод builder-образов на builder/distroless + os-pm. Использовать когда пользователь говорит "мигрируй на delivery-kit", "перепиши сборку на dk3", "werf-to-delivery-kit".
---

# werf-to-delivery-kit

Процедура миграции сборочных инструкций модуля (Deckhouse module) с werf на delivery-kit v3. Skill self-contained: правила синтаксиса, справочник директивы `packages`, порядок стадий и стоп-условия — внутри. Синтаксис соответствует delivery-kit **v3.4.0+** (`manager`, `%secret%` в `packages[].env`, `vex`); при сомнениях сверяться с `docs/pages_en/usage/build/stapel/instructions.md` этого репозитория. Скилл не зависит от CI-системы модуля: входные данные (файл базовых образов, версия delivery-kit) запрашиваются у пользователя, а настройка CI остаётся за ним (см. §0).

## Ключевая идея delivery-kit v3

При включённом SBOM (`build.sbom.enable: true`) **все shell-стадии выполняются в изолированном окружении без доступа к сети** (network=none). delivery-kit сам выводит предупреждение: `Network is disabled for shell stages (build.sbom.enable is true). Declare dependencies via 'packages' directive.`

Поэтому любое сетевое взаимодействие из `shell:` обязано переехать в декларативные директивы:

| Было в shell | Стало |
|---|---|
| `git clone --branch <tag> <url>` | директива `git:` с `url:` + `tag:`/`branch:`/`commit:` |
| `pm install <pkgs>`, `apt/apk/yum install` | `packages:` type `os-pm` (inline-список в `spec:`) |
| `go mod download` | `packages:` type `go-mod` |
| `pip install`, `poetry install`, `uv sync` | `packages:` type `python-pip` / `python-poetry` / `python-uv` |
| `npm ci`, `yarn install`, `pnpm install` | `packages:` type `javascript-npm` / `javascript-yarn` / `javascript-pnpm` |
| `cargo fetch/build` (скачивание crates) | `packages:` type `rust-cargo` |
| `luarocks install` | `packages:` type `lua-rock` |
| `curl/wget <url>` для скачивания артефактов | запрещено; артефакт должен приходить через pm (см. стоп-условие) |
| `import:` бинарей/библиотек из базовых образов (coreutils, bash, jq, tini…) | `packages:` type `os-pm` (в финальный distroless — через `-runtime-artifact`, см. §3) |
| `npm install -g yarn` / `pip install uv` — менеджер, которого нет в базовом образе | предыдущая `packages`-запись ставит менеджер, следующая ссылается на него через `manager:` (см. §3) |
| `export GOPROXY=$(cat /run/secrets/…)`, `~/.netrc` с токеном в shell | `packages[].env` с `%secret:ID%` (см. §3) |
| образы `*-vex-artifact` (`cosign attest` + `curl` в Vault в shell) | директива `vex:` на финальном образе (см. §3) |

## 0. Инвентаризация

1. Найти все сборочные файлы: корневой `werf.yaml`, инклюды (обычно `.werf/**/*.yaml`), все `images/*/werf.inc.yaml`.
2. Определить, **какой файл базовых образов читает конфиг** — найти `.Files.Get "<путь>"` в `werf.yaml`/инклюдах (типично `base_images.yml` в корне, `build/base-images/deckhouse_images.yml`, `build/base_deckhouse_images.yml` — в каждом модуле своё). Этот путь не менять: сюда будет положен актуальный каталог. Версию каталога в сборочные инструкции НЕ хардкодить — только читать сам файл.
3. **Получить актуальный каталог — у пользователя, не из CI.** Способ доставки файла (скачивание в `before_script`, шаг GitHub Action, коммит в репо) у каждого модуля свой, локально копии может не быть или она устарела. Порядок:
   - если задана env `BASE_IMAGES_FILE` — взять файл по этому пути;
   - иначе если файл по пути из п. 2 существует и его `# version=` (первая строка) ≥ v3.0.0 — использовать его;
   - иначе **спросить пользователя**: путь к локальному `base_images.yml` версии ≥ v3.0.0 либо номер версии для скачивания (каталог публикуется командой container-base как generic package `deckhouse/container-base/base-images` в fox.flant.com, файл `base_images/<version>/base_images.yml`; нужен доступ пользователя). Без каталога ≥ v3.0.0 миграцию не начинать — в более старых нет `builder/distroless`, `base/distroless`, `pm` и pm-пакетов.
   - полученный файл положить по пути из п. 2 (если файл в `.gitignore`/`allowUncommittedFiles` — не коммитить; если он tracked — коммитить обновлённую версию) и запомнить его `# version=` для отчёта.
4. Версия delivery-kit: нужен бинарь ≥ v3.4.0 (`vX.Y.Z-dk.N`). Если пользователь не указал путь к бинарю для верификации (§5) — спросить (либо собрать из тега этого репозитория: `CGO_ENABLED=0 go build -tags "dfrunsecurity dfrunnetwork dfrunmount dfssh containers_image_openpgp" -o /tmp/dk-werf ./cmd/werf`). CI-конфиг модуля **не править**: где и как задаются версии werf/delivery-kit и каталога (переменные `.gitlab-ci.yml`, внешний GitHub Action, шаблоны) — у каждого модуля своё. В финальном отчёте выдать пользователю две величины, которые он должен обеспечить в CI: версию каталога, по которой шла миграция, и минимальную версию delivery-kit. Попутно проверить `werf-giterminism.yaml`: файл каталога должен быть либо tracked, либо в `allowUncommittedFiles`.
5. Составить список всех образов и для каждого зафиксировать: базовый образ, импорты, shell-инструкции с сетью, git clone, а также все include-шаблоны (`image-build.build`, `fuzz image`, `vex mitigation` и т.п.) — их тела тоже вызывают бинари, которые нужно учесть в `os-pm`.

## 1. Правило базовых образов (жёсткое)

- **Все** базовые образы и все бинари/библиотеки берутся ТОЛЬКО из файла базовых образов (`base_images.yml`). Он содержит и builder-образы, и рантайм-базы, и pm-пакеты (coreutils, bash, sed, tini и т.д. — `# from: base/scratch`). Базовые образы применяются исключительно как `from:`; бинари из них в образы попадают только через `packages: os-pm` (см. §3), а не через `import:`.
- Единственное исключение из файла — встроенный `from: scratch` (пустой образ werf) для bundle/release-образов, состоящих только из `import`/`git`. `base/scratch` из файла для этого не использовать.
- **Единый builder — `builder/distroless`.** Вся сборка любого модуля делается на distroless-образах: сборочные (src-artifact, build, runtime-artifact, вспомогательные вроде images-digests) — `from: builder/distroless`, финальные — `from: base/distroless`. В `builder/distroless` есть `pm`, и весь тулчейн (`golang`, `node`, `make`, `git`, `sed`, `gnu-gcc`, `svace` и т.д.) декларируется через `os-pm` — так он попадает в SBOM. Специализированные builder'ы (`builder/golang-*`, `builder/node-alpine`, `builder/alpine`, `builder/src`, `builder/native` и т.п.) при миграции заменять на `builder/distroless`, даже если они есть в файле базовых образов. Следствие: в `spec:` нужно перечислять **всё**, что вызывает shell — в `builder/distroless` из коробки только busybox и `pm`. **На busybox не полагаться**: его апплеты (`sed`, `cp`, `find`, `tar`…) не считать доступными — набор и симлинки не гарантированы, а поведение отличается от GNU (`sed -i` и т.п.). Любая команда в `shell:` — в т.ч. `sed`, `cp`, `find`, `ldd`, `make`, `git` — требует свой пакет в `spec:` (`sed`, `coreutils`, `findutils`, `ldd`, `make`, `git`).
- **`svace` обязателен** в `spec:` каждого образа, где сборка идёт через `include "image-build.build"` (шаблон при `SVACE_ENABLED=true` вызывает `svace build`). То, что при обычной сборке ветка не рендерится — не повод убирать пакет: `spec` должен покрывать все ветки шаблонов. Аналогично проверять тела других include'ов на вызываемые бинари.
- **Не трогать `/bin`, `/sbin`, `/lib`, `/lib64` в `/relocate`.** В `base/distroless` это симлинки на `/usr/bin` и `/usr/lib`; если в `-runtime-artifact` создать реальный каталог `/relocate/bin` (например, ради `ln -sf /usr/bin/bash /relocate/bin/bash`), импорт в `/` перезапишет симлинк каталогом и сломает образ. Бинари класть только в `/relocate/usr/bin` — `/bin/sh`, `/bin/bash` будут работать через симлинк базы (старые `import ... to: /bin/bash` переписывать в `/usr/bin/bash`).
- **Ловушка `builder/distroless`:** в образе нет каталога `$HOME` (`/root`). Перед записью `~/.npmrc`, `~/.yarnrc`, `~/.gitconfig`, `~/.ssh/config` — `mkdir -p ~/.ssh` (создаёт и `$HOME`).
- Никаких прямых ссылок на внешние registry, docker.io, `ubuntu:...` и т.п.
- **Стоп-условие:** если для сборки нужен OS-пакет/бинарь/библиотека, которых нет в файле базовых образов — прекратить переписывание этого образа, зафиксировать список недостающих пакетов и сообщить пользователю, что нужно идти в команду container-base с запросом на добавление. Не искать обходных путей (curl, git clone бинарей, сборка из сторонних источников). Исключение — менеджеры языковых экосистем (yarn, pnpm, uv, poetry): их ставит предыдущая `packages`-запись, см. `manager:` в §3.

Типовой паттерн подключения (значения из файла — digest'ы):

```yaml
# .werf/stages/base-images.yaml (или аналог)
{{- $baseImages := .Files.Get "base_images.yml" | fromYaml -}}
# ... для каждого ключа рендерится:
---
image: {{ $k }}
from: {{ $baseImages.REGISTRY_PATH }}@{{ $v }}
final: false
```

Далее внутренние образы ссылаются на них по имени: `from: builder/distroless` (без тега). Каталог, по которому шла миграция, и каталог, который подкладывает CI, должны быть одной версии — иначе локальный рендер и CI собирают разные digest'ы (версию сообщить пользователю, §0 п. 4).

## 2. Корневой werf.yaml

Обязательная запись в секции `build:`:

```yaml
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
```

Правила валидации схемы: `standard` без `enable: true` — ошибка; `enable: true` без `standard` — ошибка. Указывать всегда оба поля. Единственный поддерживаемый стандарт — `cyclonedx@1.6`. Опционально существует блок `gost:` (`attackSurface`, `securityFunction`) — добавлять только если этого требует проект.

## 3. Правила синтаксиса dk3 (переписывание)

### from вместо fromImage

- Каждый образ начинается с `from:`. `fromImage` — deprecated-алиас; одновременное указание `from` и `fromImage` — ошибка конфигурации.
- Внутренний образ (описан в этом же werf-конфиге): `from: <имя-образа>` — **без тега**.
- Внешний образ: `from: <registry>/<repo>:<tag>` или `@sha256:<digest>` — тег/digest обязателен. Внешние допустимы только из файла базовых образов (правило §1).
- Образ не может ссылаться сам на себя (`cannot use itself as base image`).

### import и dependencies

В `import:` и `dependencies:` поле `image:` заменено на `from:` (`image:` — deprecated-алиас).

**Строгое правило: import разрешён только между собираемыми образами проекта** (src-artifact, build, runtime-artifact и т.п.). Импортировать бинари/библиотеки из базовых образов (ключи base_images.yml: coreutils, bash, sed, grep, jq, tini, ssh-static, util-linux, `builder/golang-debian` и т.д.) **запрещено** — такие импорты заменяются установкой пакетов через `packages: os-pm` (имена пакетов совпадают с ключами base_images.yml). Базовые образы используются ТОЛЬКО в `from:`.

Бинарь `pm` есть в `builder/distroless`, но НЕТ в `base/distroless`. Поэтому бинари для финального образа на `base/distroless` ставятся в промежуточный `-runtime-artifact` на `builder/distroless` и релоцируются вместе с библиотеками (через `ldd`) в `/relocate`, который импортируется в `/` финального образа:

```yaml
image: {{ $.ImageName }}-runtime-artifact
final: false
from: builder/distroless
packages:
  - type: os-pm
    spec: [ldd, bash, coreutils, tini, ssh-static]
shell:
  install:
    - |
      {{- include "load copy functions" . | indent 6 }}   # do_copy / do_copy_with_dependencies из .werf/defines/copy.tmpl
    - do_copy_with_dependencies /relocate /usr/bin/bash /usr/bin/sh /usr/bin/cp /usr/bin/tini /usr/bin/ssh
---
image: {{ $.ImageName }}
from: base/distroless
import:
  - from: {{ $.ImageName }}-runtime-artifact   # собираемый образ — ок
    add: /relocate
    to: /
    before: install
# БЫЛО (запрещено теперь):
#  - image: coreutils
#    add: /usr/bin/cp
```

Частные случаи: `awk` — это пакет `gawk` + `ln -sf gawk /relocate/usr/bin/awk`; `getent`/`libnss_*` (раньше импортировали из `builder/golang-debian`) — пакет `gnu-glibc`, NSS-модули `ldd` не видит, копировать `libnss_*.so*` явно. Старые импорты вида `to: /bin/bash`, `to: /bin/sh` переписывать на `/usr/bin/...` и не создавать `/relocate/bin` (см. §1 про симлинки в `base/distroless`).

### git clone → директива git

Каждый `git clone` в shell переписывается на remote-git запись с явным `tag:` (предпочтительно), `branch:` или `commit:`:

```yaml
git:
  - url: {{ env "SOURCE_REPO" }}/org/repo.git
    tag: v1.2.3
    add: /
    to: /src/app
    stageDependencies:
      install: ["**/*"]
```

- Секрет `SOURCE_REPO` из `secrets:` + `$(cat /run/secrets/SOURCE_REPO)` больше не нужен для клонирования — url задаётся шаблоном; проверить, что `werf-giterminism.yaml` разрешает используемые env в шаблонах.
- При необходимости аутентификации есть `basicAuth:` (`username`, `password.env` / `password.src` / `password.value` — ровно один источник).
- Шаги вида `git rev-parse HEAD > .git-commit` больше невыполнимы (нет `.git` и нет shell-доступа к клону до gitArchive): если commit/sha нужен в образе — записать известный тег/версию через `echo` в shell, либо убрать использование.
- `rm -rf /src/*/.git` больше не нужен.

### stageDependencies без инструкций стадии — запрещено

`git[].stageDependencies.<стадия>` (install/beforeSetup/setup) допустим ТОЛЬКО если у образа есть соответствующие `shell.<стадия>` инструкции — иначе сборка падает (`git.stageDependencies.<stage> is defined, but no <stage> instructions are provided`). Типовые случаи при миграции:

- Убрали shell-логику (git clone → `git:`, установка пакетов → `packages:`), а `stageDependencies.install` остался — **удалить** его. Инвалидация по изменениям файлов и так происходит на стадии gitArchive.
- Антипаттерн с заглушкой — переписать, удалив и заглушку, и stageDependencies:

```yaml
# БЫЛО (заглушка ради валидного stageDependencies) — так нельзя:
git:
  - add: /hooks/go
    to: /src/hooks/go
    stageDependencies:
      install: ["**/go.mod", "**/go.sum", "**/*.go", "**/testdata/**"]
shell:
  install:
    - echo "src artifact"

# СТАЛО:
git:
  - add: /hooks/go
    to: /src/hooks/go
```

- `stageDependencies.packages` валиден при наличии директивы `packages:` у образа — использовать для файловых манифестов (`go.mod`/`go.sum`, `package.json`/`yarn.lock` и т.п.). Для `os-pm` не нужен: spec лежит inline в самом werf-конфиге, его изменение само инвалидирует стадию.

### Установка пакетов → директива packages

Справочник типов (spec/lock по умолчанию и что выполняется на стадии packages):

| type | spec (default) | lock (default) | команда |
|---|---|---|---|
| `os-pm` | inline-список в `spec:` | — | `pm install <пакеты>` |
| `go-mod` | `go.mod` | `go.sum` | `cd <workdir> && go mod download` |
| `python-uv` | `pyproject.toml` | `uv.lock` | `uv sync --frozen` |
| `python-pip` | `requirements.txt` | — | `pip install --no-cache-dir -r <spec>` |
| `python-poetry` | `pyproject.toml` | `poetry.lock` | `poetry sync --no-root` |
| `rust-cargo` | `Cargo.toml` | `Cargo.lock` | `cargo fetch` |
| `javascript-npm` | `package.json` | `package-lock.json` | `npm ci` |
| `javascript-yarn` | `package.json` | `yarn.lock` | yarn install (frozen) |
| `javascript-pnpm` | `package.json` | `pnpm-lock.yaml` | pnpm install (frozen) |
| `lua-rock` | rockspec | — | luarocks |

Общие поля: `workdir` (путь внутри контекста, где лежат spec/lock; для `os-pm` указывать **нельзя** — ошибка валидации), `spec` (для файловых типов — путь к манифесту; для `os-pm` — **только inline-список** имён пакетов, путь к файлу — ошибка валидации `use inline package list instead of file path`), `lock` (путь к lock-файлу; для `os-pm` не поддерживается), `manager` (только файловые типы — путь к исполняемому файлу менеджера внутри `workdir` предыдущей `packages`-записи, см. ниже), `env` (map переменных для команды установки; shell-конструкции `$(...)`/`$VAR` не вычисляются — вместо них ссылки на секреты, см. ниже).

**Секреты в `packages[].env`.** Значение может ссылаться на секрет из `secrets:` образа: `%secret:<id>%` (содержимое) или `%secret_path:<id>%` (`/run/secrets/<id>`). Секрет резолвится в момент запуска менеджера и не попадает ни в digest стадии, ни в слои. Это единственный правильный способ передать `GOPROXY` и токен для приватных go-модулей; `export GOPROXY=$(cat /run/secrets/…)` и `~/.netrc` в shell больше не нужны (и оставляли токен в слоях артефакта). Стандартный набор для Go-образа модуля Deckhouse (блок `GOPRIVATE`/`GIT_CONFIG_*` нужен только если `go.mod` ссылается на модули в приватном GitLab):

```yaml
secrets:
- id: GOPROXY
  value: {{ .GOPROXY }}
- id: CI_JOB_TOKEN
  value: "{{ env "CI_JOB_TOKEN" }}"
packages:
  - type: go-mod
    workdir: /src
    env:
      GOPROXY: "%secret:GOPROXY%"
      GOPRIVATE: fox.flant.com/*
      GIT_CONFIG_COUNT: "1"
      GIT_CONFIG_KEY_0: url.https://gitlab-ci-token:%secret:CI_JOB_TOKEN%@fox.flant.com/.insteadOf
      GIT_CONFIG_VALUE_0: https://fox.flant.com/
```

**`manager` — менеджер, которого нет в base_images (yarn, pnpm, uv, poetry).** Это единственный способ его получить: предыдущая `packages`-запись ставит его из запиненного lock-файла (хранится в каталоге образа: `images/<img>/tools/yarn/{package.json,package-lock.json}` с единственной зависимостью `"yarn": "<version>"`; lock генерируется локально `npm install --package-lock-only --ignore-scripts`), следующая ссылается на него. Путь вне `workdir` предыдущей записи (в т.ч. голое имя) отклоняется. В shell менеджер вызывать по тому же полному пути (в `PATH` его нет):

```yaml
git:
  - add: {{ $.ImagePath }}/tools/yarn
    to: /tools/yarn
    stageDependencies:
      packages: ["package.json", "package-lock.json"]
packages:
  - type: os-pm
    spec: [node, git]
  - type: javascript-npm
    workdir: /tools/yarn
  - type: javascript-yarn
    workdir: /app
    manager: /tools/yarn/node_modules/.bin/yarn
shell:
  install:
    - cd /app && NODE_ENV=production /tools/yarn/node_modules/.bin/yarn build
```

Конфиги менеджеров (`~/.npmrc`/`~/.yarnrc` с реестром-прокси, `~/.gitconfig` с `insteadOf`, `~/.ssh/config`) готовятся в `shell.beforeInstall` — она идёт **до** стадии packages (см. порядок стадий), секреты там уже смонтированы; не забыть `mkdir -p ~` (§1). Замена URL реестров в `yarn.lock` через `sed` делается в `install` образа-источника (src-artifact), до импорта.

**os-pm** (замена `pm install ...` / apt / apk) — пакеты объявляются **прямо в werf-конфиге**, отдельных файлов (`pm.yaml`/`pm.lock`) НЕТ, формат больше не поддерживается delivery-kit:

```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1        # пиннинг версии через ==
      - ca-certificates     # без версии — последняя из каталога
```

**Правила os-pm:**

- `spec` — непустой список строк `имя` или `имя==версия`; `workdir` и `lock` запрещены.
- **Одна** запись `os-pm` на образ (`the packages section allows only one os-pm directive`) — все OS-пакеты собирать в один список. Файловых записей (например, несколько `go-mod` для разных репозиториев в одном образе) может быть сколько угодно.
- Отдельные `git:`-записи для доставки pm-файлов и `stageDependencies.packages` не нужны — spec лежит в самом конфиге, его изменение само инвалидирует стадию.
- Имена пакетов сверять с `base_images.yml` (могут отличаться от apt/apk: например `libssl-dev` → `openssl-devel`, `awk` → `gawk`, `getent`/`libnss_*` → `gnu-glibc`); если пакета нет в каталоге — стоп-условие §1.
- В `builder/distroless` нет ничего, кроме busybox и `pm`, и на busybox не полагаемся (§1): все инструменты, которые вызывает shell и тела include'ов (`golang`, `make`, `git`, `sed`, `coreutils`, `svace`, `ldd`…), перечислять в `spec:`. Типичный симптом пропуска — `command not found` на стадии install (иногда только в CI-ветке с `SVACE_ENABLED=true`).

Бинарь `pm` и env `PACKAGES_VERSION`/`REGISTRY` есть в `builder/distroless`; в `base/distroless` и `scratch` их нет — для них см. паттерн `-runtime-artifact` выше.

**go-mod** для сборки Go из склонированного репозитория. `workdir` — каталог с `go.mod` собираемого модуля; в монорепо с `go.work` это подкаталог модуля, а не корень репозитория:

```yaml
image: {{ $.ImageName }}-build
final: false
from: builder/distroless
git:
  - url: {{ env "SOURCE_REPO" }}/org/repo.git
    tag: v1.2.3
    add: /
    to: /src/app
secrets:
- id: GOPROXY
  value: {{ .GOPROXY }}
packages:
  - type: os-pm
    spec: [golang, make, git]
  - type: go-mod
    workdir: /src/app
    env:
      GOPROXY: "%secret:GOPROXY%"
shell:
  install:
    - cd /src/app && CGO_ENABLED=0 go build -o /out/app .   # сеть не нужна: модули уже скачаны
```

### VEX → директива vex

В модулях Deckhouse есть образы `<img>-vex-artifact` (шаблон `vex mitigation` из `.werf/defines/vex.tmpl` + база `base/vex`), которые в shell делают `cosign attest` в registry и `curl` в Vault. Они `final: true`, собираются всегда и без сети ломают сборку. Замена — нативная директива на финальном образе (путь от корня git, файл должен быть tracked и валидным OpenVEX JSON); delivery-kit публикует его как OCI-referrer (DSSE/in-toto, predicate `https://openvex.dev/ns/v0.2.0`):

```yaml
image: {{ $.ImageName }}
from: base/distroless
vex: images/{{ $.ImageName }}/known_vulnerabilities.vex
---
image: bundle
from: scratch
vex: known_vulnerabilities.vex
```

После этого удалить `include "vex mitigation"`, сам `vex.tmpl` и образ `base/vex`. Совместимость с внешним сканером (ожидает ли он cosign-аттестацию с подписью Vault) — уточнить у пользователя, это не решается в сборочном конфиге.

### Порядок стадий (важно для понимания)

`from → beforeInstall → dependenciesBeforeInstall → gitArchive → packages → install → dependenciesAfterInstall → beforeSetup → setup → ...`

Стадия `packages` идёт **после** gitArchive (spec/lock и исходники уже в контейнере) и **до** `install` — поэтому в `shell.install` зависимости уже установлены. Стадия `packages` — единственная пользовательская стадия с доступом в сеть. Следствия: `beforeInstall` выполняется **до** packages и годится для подготовки конфигов менеджеров (без сети); `import … before: install` попадает в контейнер до packages, поэтому `workdir` файловых типов может указывать на импортированный каталог; инструменты, установленные через `os-pm`, в `beforeInstall` ещё недоступны.

### Инвалидация кэша

Для триггера пересборки стадии packages при изменении файловых spec/lock (go-mod, javascript-* и т.п.):

```yaml
git:
  - add: /
    to: /
    stageDependencies:
      packages:
        - go.mod
        - go.sum
```

Для `os-pm` отдельная инвалидация не нужна — inline `spec:` является частью конфига, его изменение само пересобирает стадию.

## 4. Порядок работы

1. Прочитать файл базовых образов, построить множество доступных образов/пакетов.
2. Переписать корневой `werf.yaml`: добавить `build.sbom`, проверить `configVersion: 1`.
3. Пройти по каждому `werf.inc.yaml` и инклюдам:
   - `fromImage:` → `from:`; в `import:`/`dependencies:` `image:` → `from:`;
   - любой `from: builder/*`, кроме `builder/distroless`, → `builder/distroless` + тулчейн в `os-pm`; финальные образы — `base/distroless`; `base/scratch` для bundle/release → `scratch`;
   - импорты из базовых образов (ключей base_images.yml) → `packages: os-pm` (для финальных образов на `base/distroless` — через `-runtime-artifact` + `/relocate`); оставить только импорты между собираемыми образами;
   - каждый `git clone` → `git:` c `url` + `tag`/`branch`;
   - каждую установку пакетов → `packages:` (OS-пакеты — один inline `spec:` список у `os-pm`, версии через `==` если были зафиксированы; языковые экосистемы — файловые манифесты go.mod/package.json и т.п.; отсутствующий менеджер — через `manager:`);
   - `GOPROXY`, `CI_JOB_TOKEN`/`~/.netrc`, `GOPRIVATE` из shell → `packages[].env` с `%secret:ID%`;
   - `include "vex mitigation"` → `vex:` на финальном образе; удалить `vex.tmpl`, `base/vex`, `packages-proxies.tmpl` (`apk`/`apt` proxy-хелперы больше не нужны);
   - удалить из shell всё сетевое (`curl`, `wget`, `go mod download`, `git`, `pm install`, `npm install -g`); чистые локальные команды (cp, sed, build при скачанных зависимостях) остаются в shell — но каждый вызываемый ими бинарь должен быть в `spec:` os-pm;
   - после удаления/переноса shell-инструкций проверить каждый `stageDependencies.<стадия>`: если у образа больше нет `shell.<стадия>` — удалить stageDependencies (и не добавлять shell-заглушки ради них);
   - убрать ставшие ненужными `secrets:` (например SOURCE_REPO для clone).
4. На каждом шаге сверяться с §1: чего-то нет в базовых образах → остановиться и доложить (список недостающего, для какого образа).
5. В финальном отчёте выдать пользователю требования к CI (сам CI не править, §0 п. 4): версия каталога базовых образов, по которой шла миграция (`# version=`), и минимальная версия delivery-kit (≥ v3.4.0). Если каталог tracked в репо — обновлённую копию закоммитить вместе с миграцией.

Типовые образы модульной инфраструктуры Deckhouse, которые **не переписывать**, а зафиксировать в отчёте (сеть в shell не выражается директивами), если они есть в модуле: fuzz-образы (`.werf/defines/fuzz.tmpl`: `curl` aws-cli/mc, S3, `go install`) — они `final: false` и собираются только отдельными job'ами; svace-ветка `image-build.tmpl` (`ssh`/`rsync` на analyze-сервер при `SVACE_ENABLED=true`). Решение по ним — за пользователем.

## 5. Верификация

```bash
# рендер и граф без сборки — ловят ошибки схемы (fromImage+from, workdir у os-pm, второй os-pm,
# manager вне workdir, необъявленный %secret%, sbom без standard, vex-файл не в git и т.п.).
# Шаблоны обычно требуют env из werf-giterminism.yaml (allowEnvVariables) — подставить заглушки для всех,
# что используются в `env "..."`; типично SOURCE_REPO и непустой CI_JOB_TOKEN. `werf` здесь — бинарь
# delivery-kit ≥ v3.4.0 (§0 п. 4). `--dev` берёт незакоммиченные изменения; если репозиторий имеет
# несколько worktree, `--dev` конфликтует между ними — тогда закоммитить и запускать без флага.
SOURCE_REPO=https://example.invalid CI_JOB_TOKEN=x werf config render --dev >/dev/null
SOURCE_REPO=https://example.invalid CI_JOB_TOKEN=x werf config graph --dev >/dev/null

# не осталось запрещённых паттернов
grep -rn "fromImage" werf.yaml .werf/ images/*/werf.inc.yaml
grep -rnE "git clone|curl |wget |go mod download|pm install|npm install|apt(-get)? install|apk add|\.netrc|cat /run/secrets/GOPROXY" images/*/werf.inc.yaml .werf/
grep -rnE "vex mitigation|base/vex|base/scratch" werf.yaml .werf/ images/*/werf.inc.yaml
# единственный допустимый builder — builder/distroless
grep -rnE "from: builder/" werf.yaml .werf/ images/*/werf.inc.yaml | grep -v "builder/distroless"
# импорты только из собираемых образов: сверить список источников с ключами base_images.yml — пересечений быть не должно
grep -rhn "^\s*- from:" .werf/ images/*/werf.inc.yaml | sed 's/.*from: //' | sort -u
# каждый stageDependencies.install/beforeSetup/setup должен иметь парные shell-инструкции в том же образе
grep -rn -A3 "stageDependencies:" images/*/werf.inc.yaml .werf/
# каждый образ с include "image-build.build" должен иметь svace в spec os-pm (сравнить два списка пофайлово)
grep -ln 'image-build.build' images/*/werf.inc.yaml; grep -ln '\bsvace\b' images/*/werf.inc.yaml
# не создаём каталоги, которые в base/distroless являются симлинками
grep -rnE "/relocate/(bin|sbin|lib|lib64)\b|to: /(bin|sbin|lib|lib64)/" images/*/werf.inc.yaml
# версия каталога, по которой шла миграция (для отчёта; путь — из .Files.Get в конфиге)
head -1 <путь-к-каталогу>
```

Затем пробная сборка (`werf build`): в логе должно быть предупреждение об отключении сети для shell-стадий, сборка должна пройти без сетевых ошибок. Типовые падения на первом прогоне: `command not found` (бинарь не в `spec:` os-pm), `~/.x: No such file or directory` (нет `$HOME`, §1), `symbol lookup error` у пакета из pm (баг сборки пакета в container-base — проверить более новую версию каталога, не обходить в конфиге). Проверить SBOM можно командами `werf attest ls|get|verify` (скрыты из help).

## Стоп-условия (повторно, критично)

- Нет нужного OS-пакета/образа в файле базовых образов → **прекратить** переписывание, сообщить пользователю: запросить пакет у команды container-base. Для менеджеров языковых экосистем (yarn, pnpm, uv, poetry) сначала применить `manager:` (§3).
- Не удаётся заменить сетевую shell-команду ни одной директивой (`git:`/`packages:`/`vex:`) → не оставлять её в shell "как есть" и не изобретать обходы, а зафиксировать проблему и спросить пользователя (типовые случаи — fuzz и svace, см. §4).
- Пакет из pm не работает (`symbol lookup error`, нет манифеста в registry) → это дефект container-base, не конфига: сообщить пользователю, не тащить бинарь/библиотеку из другого базового образа через `import`.

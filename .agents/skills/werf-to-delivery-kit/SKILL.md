---
name: werf-to-delivery-kit
description: Миграция сборочных конфигов модуля с werf на delivery-kit v3 (dk3). Переписывает werf.yaml и все images/*/werf.inc.yaml на новый синтаксис — from вместо fromImage, включение SBOM (cyclonedx@1.6), замена сетевых shell-инструкций (git clone, pm install, go mod download и т.п.) на директивы git и packages. Использовать когда пользователь говорит "мигрируй на delivery-kit", "перепиши сборку на dk3", "werf-to-delivery-kit".
---

# werf-to-delivery-kit

Процедура миграции сборочных инструкций модуля (Deckhouse module) с werf на delivery-kit v3. Skill self-contained: правила синтаксиса, справочник директивы `packages`, порядок стадий и стоп-условия — внутри.

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
| `import:` бинарей/библиотек из базовых образов (coreutils, bash, jq, tini…) | `packages:` type `os-pm` |

## 0. Инвентаризация

1. Найти все сборочные файлы: корневой `werf.yaml`, инклюды (обычно `.werf/**/*.yaml`), все `images/*/werf.inc.yaml`.
2. Найти файл базовых образов: `base_images.yml` или `base_images.yaml` в корне репозитория, либо `build/base_deckhouse_images.yml`. Локальная копия лежит в корне для дебага; в CI файл приезжает автоматически по переменной `BASE_IMAGES_VERSION` (например `v1.3.22`) — версию файла НЕ хардкодить в сборочные инструкции, только читать сам файл через `.Files.Get`.
3. Составить список всех образов и для каждого зафиксировать: базовый образ, импорты, shell-инструкции с сетью, git clone.

## 1. Правило базовых образов (жёсткое)

- **Все** базовые образы и все бинари/библиотеки берутся ТОЛЬКО из файла базовых образов (`base_images.yml`). Он содержит и builder-образы, и рантайм-базы, и pm-пакеты (coreutils, bash, sed, tini и т.д. — `# from: base/scratch`). Базовые образы применяются исключительно как `from:`; бинари из них в образы попадают только через `packages: os-pm` (см. §3), а не через `import:`.
- Никаких прямых ссылок на внешние registry, docker.io, `ubuntu:...` и т.п.
- **Стоп-условие:** если для сборки нужен пакет/бинарь/библиотека, которых нет в файле базовых образов — прекратить переписывание этого образа, зафиксировать список недостающих пакетов и сообщить пользователю, что нужно идти в команду container-base с запросом на добавление. Не искать обходных путей (curl, git clone бинарей, сборка из сторонних источников).

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

Далее внутренние образы ссылаются на них по имени: `from: builder/golang` (без тега).

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

**Строгое правило: import разрешён только между собираемыми образами проекта** (src-artifact, build, runtime-artifact и т.п.). Импортировать бинари/библиотеки из базовых образов (ключи base_images.yml: coreutils, bash, sed, grep, jq, tini, ssh-static, util-linux и т.д.) **запрещено** — такие импорты заменяются установкой пакетов через `packages: os-pm` (имена пакетов совпадают с ключами base_images.yml). Базовые образы используются ТОЛЬКО в `from:`. os-pm работает и на минимальных базах (distroless/scratch) — нужен лишь бинарь `pm` в образе (в крайнем случае приносится import'ом из собираемого carrier-образа) и секреты/env `PACKAGES_VERSION`, `REGISTRY`.

```yaml
import:
  - from: {{ $.ImageName }}-build   # собираемый образ — ок
    add: /build/dist/app
    to: /usr/local/bin/app
    before: install
# БЫЛО (запрещено теперь):
#  - image: coreutils
#    add: /usr/bin/cp
# СТАЛО: пакет coreutils в inline spec директивы packages: os-pm этого образа
```

### git clone → директива git

Каждый `git clone` в shell переписывается на remote-git запись с явным `tag:` (предпочтительно), `branch:` или `commit:`:

```yaml
git:
  - url: {{ env "SOURCE_REPO" }}/argoproj/argo-cd.git
    tag: v3.4.4-delivery.4
    add: /
    to: /src/argo-cd
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

Общие поля: `workdir` (путь внутри контекста, где лежат spec/lock; для `os-pm` указывать **нельзя** — ошибка валидации), `spec` (для файловых типов — путь к манифесту; для `os-pm` — **только inline-список** имён пакетов, путь к файлу — ошибка валидации `use inline package list instead of file path`), `lock` (путь к lock-файлу; для `os-pm` не поддерживается), `env` (map переменных, передаются префиксом к команде; секреты в значения не класть).

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
- Отдельные `git:`-записи для доставки pm-файлов и `stageDependencies.packages` не нужны — spec лежит в самом конфиге, его изменение само инвалидирует стадию.
- Имена пакетов сверять с `base_images.yml` (могут отличаться от apt/apk: например `libssl-dev` → `openssl-devel`); если пакета нет в каталоге — стоп-условие §1.

Бинарь `pm` должен присутствовать в базовом образе (builder-образы из файла базовых образов его содержат); на scratch/distroless его можно принести `import:` из собираемого carrier-образа + секреты/env `PACKAGES_VERSION`, `REGISTRY`. Если недоступен — стоп-условие §1.

**go-mod** для сборки Go из склонированного репозитория:

```yaml
image: {{ $.ImageName }}-build
final: false
from: builder/golang
git:
  - url: {{ env "SOURCE_REPO" }}/org/repo.git
    tag: v1.2.3
    add: /
    to: /src/app
packages:
  - type: go-mod
    workdir: /src/app
shell:
  install:
    - cd /src/app && CGO_ENABLED=0 go build -o /out/app .   # сеть не нужна: модули уже скачаны
```

### Порядок стадий (важно для понимания)

`from → beforeInstall → dependenciesBeforeInstall → gitArchive → packages → install → dependenciesAfterInstall → beforeSetup → setup → ...`

Стадия `packages` идёт **после** gitArchive (spec/lock и исходники уже в контейнере) и **до** `install` — поэтому в `shell.install` зависимости уже установлены. Стадия `packages` — единственная пользовательская стадия с доступом в сеть.

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
   - импорты из базовых образов (ключей base_images.yml) → `packages: os-pm`; оставить только импорты между собираемыми образами;
   - каждый `git clone` → `git:` c `url` + `tag`/`branch`;
   - каждую установку пакетов → `packages:` (OS-пакеты — inline `spec:` список у `os-pm`, версии через `==` если были зафиксированы; языковые экосистемы — файловые манифесты go.mod/package.json и т.п.);
   - удалить из shell всё сетевое (`curl`, `wget`, `go mod download`, `git`, `pm install`); чистые локальные команды (cp, sed, build при скачанных зависимостях) остаются в shell;
   - после удаления/переноса shell-инструкций проверить каждый `stageDependencies.<стадия>`: если у образа больше нет `shell.<стадия>` — удалить stageDependencies (и не добавлять shell-заглушки ради них);
   - убрать ставшие ненужными `secrets:` (например SOURCE_REPO для clone).
4. На каждом шаге сверяться с §1: чего-то нет в базовых образах → остановиться и доложить (список недостающего, для какого образа).

## 5. Верификация

```bash
# рендер конфига без сборки — ловит ошибки схемы (fromImage+from, workdir у os-pm, sbom без standard и т.п.)
werf config render

# не осталось запрещённых паттернов
grep -rn "fromImage" werf.yaml .werf/ images/*/werf.inc.yaml
grep -rnE "git clone|curl |wget |go mod download|pm install|apt(-get)? install|apk add" images/*/werf.inc.yaml .werf/
# импорты только из собираемых образов: сверить список источников с ключами base_images.yml — пересечений быть не должно
grep -rn "^\s*- from:" .werf/ images/*/werf.inc.yaml
# каждый stageDependencies.install/beforeSetup/setup должен иметь парные shell-инструкции в том же образе
grep -rn -A3 "stageDependencies:" images/*/werf.inc.yaml .werf/
```

Затем пробная сборка (`werf build`): в логе должно быть предупреждение об отключении сети для shell-стадий, сборка должна пройти без сетевых ошибок. Проверить SBOM можно командами `werf attest ls|get|verify` (скрыты из help).

## Стоп-условия (повторно, критично)

- Нет нужного пакета/образа в файле базовых образов → **прекратить** переписывание, сообщить пользователю: запросить пакет у команды container-base.
- Не удаётся заменить сетевую shell-команду ни одной директивой (`git:`/`packages:`) → не оставлять её в shell "как есть", а зафиксировать проблему и спросить пользователя.

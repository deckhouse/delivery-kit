---
title: Роли и процесс работы со SBOM
permalink: usage/build/sbom_workflow.html
---

Работа со SBOM разделена между двумя ролями:

| Роль | Ответственность | Что делает | Что получает |
|------|-----------------|-----------|--------------|
| **Разработчик модуля** | за SBOM модуля | описывает зависимости декларативно и собирает свои образы | **per-image SBOM** (CycloneDX 1.6) в registry, рядом с каждым образом |
| **Ответственный за SBOM** | за SBOM продукта | агрегирует per-image SBOM нужных образов и валидирует результат | **merged SBOM** (формат ИСПРАС), проходящий ИСПРАС-валидацию |

Роли независимы: разработчик модуля не работает с merge/validate, ответственный за
SBOM не собирает образы. Всё, что нужно ответственному от разработчиков, —
знать, **какие образы** (по их digest'ам) входят в продукт.

```
Разработчик модуля:             werf build   [→ werf sbom get]
                                    │
                                    ▼   per-image SBOM в registry
Ответственный за SBOM:          werf sbom merge  →  werf sbom validate
```

## Flow разработчика модуля

Вы отвечаете за модуль (приложение) и его образы. Ваша задача — собрать образы так,
чтобы у каждого в registry появился полный per-image SBOM.

### Prerequisites

- **container registry с правом на запись** — образы и SBOM-артефакты публикуются
  туда (флаг `--repo` / переменная `WERF_REPO`);
- **обогащение VCS external references** — задайте переменную окружения
  `WERF_EXTERNAL_REFS_SERVER_URL` (URL сервиса обогащения); при включённом SBOM
  она обязательна — без неё сборка завершится ошибкой.

| Переменная | Зачем | Обязательна |
|------------|-------|-------------|
| `WERF_REPO` | registry для образов и SBOM-артефактов | да |
| `WERF_EXTERNAL_REFS_SERVER_URL` | URL сервиса обогащения VCS external refs | да — без неё сборка упадёт |

```bash
export WERF_REPO="registry.example.com/my-project"
export WERF_EXTERNAL_REFS_SERVER_URL="https://purl-resolver.example.com/"
```

#### Требования к базовым образам

Базовые образы бывают двух разновидностей, и flow для них различается:

- **сборочные** (builder) — в них выполняются стадия `packages` и shell-инструкции;
  в SBOM собранного на них образа могут попадать **сборочные зависимости**
  (build-deps: компиляторы, `*-devel`-пакеты и т.п.);
- **финальные** (runtime, например distroless) — база итогового образа поставки;
  в его SBOM входят только runtime-зависимости.

Требования:

- **werf не поставляет пакетный менеджер `pm`.** Если образ использует
  `packages: type: os-pm`, его базовый образ обязан содержать бинарь `pm` в `$PATH`
  (подробнее — в описании [директивы `packages`]({{ "/usage/build/stapel/instructions.html#установка-бинарных-пакетов" | true_relative_url }}));
- **у каждого base/import-образа должен быть прикреплённый SBOM** в registry —
  иначе сборка с включённым SBOM завершится ошибкой; такие образы нужно собирать
  с `build.sbom.enable: true`;
- для file-based экосистем (`go-mod` и др.) `pm` не нужен — нужен соответствующий
  тулчейн в базовом образе (например, Go для `go mod download`).

#### Ограничения

См. раздел [«Ограничения»]({{ "/usage/build/sbom.html#ограничения" | true_relative_url }})
на странице SBOM.

### Шаг 1. Опишите зависимости в `werf.yaml`

|  |  |
|---|---|
| **Вход** | исходники модуля |
| **Что сделать** | включить SBOM и объявить все зависимости декларативно |
| **Выход** | `werf.yaml`, в котором каждая зависимость — контролируемый вход |

Включите SBOM секцией [`build.sbom`]({{ "/usage/build/sbom.html" | true_relative_url }}).
Секция действует на весь `werf.yaml`: выставив её, вы переводите в SBOM flow
**все образы проекта**. Зависимости объявите через
[`packages`]({{ "/usage/build/stapel/instructions.html#установка-бинарных-пакетов" | true_relative_url }}):

- OS-пакеты — инлайн-списком через `os-pm`;
- языковые — file-based типами (`go-mod` и др.);
- привяжите стадию `packages` к манифестам языковых зависимостей через
  `stageDependencies`.

### Шаг 2. Соберите образы: `werf build`

|  |  |
|---|---|
| **Вход** | исходники + `werf.yaml` с шага 1 |
| **Команда** | `werf build` |
| **Выход** | образы в registry; per-image SBOM-артефакт рядом с каждым образом |

Для каждого образа на этапе сборки werf:

- учитывает объявленные в `packages` зависимости (каталогизаторы syft по
  манифестам/lock-файлам, os-pm collector);
- обогащает компоненты свойствами безопасности ГОСТ (`attackSurface`,
  `securityFunction`);
- выполняет purl-resolving: обогащает VCS external references через сервис из
  `WERF_EXTERNAL_REFS_SERVER_URL`;
- подписывает SBOM, если задан ключ (`--sign-key`, опционально `--sign-cert`),
  и публикует SBOM-артефакт в registry, ассоциировав его с digest'ом образа.

**Ожидаемый результат:** сборка завершилась без ошибок; per-image SBOM
опубликованы в registry вместе с образами. На этом задача разработчика модуля
выполнена.

### Шаг 3 (опционально). Self-check: `werf sbom get`

|  |  |
|---|---|
| **Вход** | имя образа из `werf.yaml` |
| **Команда** | `werf sbom get <image>` |
| **Выход** | SBOM образа — чистый CycloneDX 1.6 JSON |

По желанию убедитесь, что SBOM вашего модуля полный:

```bash
werf sbom get <image> > sbom.json
```

`sbom get` выгружает SBOM из registry (сгенерированный на шаге 2) в stdout.
SBOM всегда ассоциирован с **digest'ом** образа; имя из `werf.yaml` — это удобный
ярлык: werf резолвит его в digest текущей сборки и по нему находит SBOM. Если
образы ещё не собраны, команда сначала запускает стандартный сборочный конвейер,
как `werf build`.

**Ожидаемый результат:** валидный JSON с `"bomFormat": "CycloneDX"` и
`"specVersion": "1.6"`; в `components` — зависимости модуля, у компонентов
проставлены свойства ГОСТ и VCS external references.

> Альтернатива позиционному имени: `werf sbom get --tag <content-based-tag>` или
> `--digest sha256:...` (взаимоисключающие, требуют `--repo`).

У разработчика модуля нет операций merge/validate — это зона ответственности
следующей роли.

## Flow ответственного за SBOM

Вы отвечаете за SBOM продукта в целом. Образы вы не собираете — работаете с
per-image SBOM, которые разработчики модулей уже опубликовали в registry. Ваша
задача — агрегировать их в единый SBOM нужной гранулярности (модуль, срез
продукта, весь продукт) и провалидировать его по схемам ИСПРАС.

### Prerequisites

- **доступ на чтение container registry**, где лежат образы и per-image SBOM;
- **digest'ы образов**, входящих в продукт. Как их получить — зависит от
  процесса: из CI-артефактов, из build-report сборки, от разработчиков модулей.
  `sbom merge` принимает **digest'ы, а не теги**;
- merge собирает SBOM только в форматах ИСПРАС: `oss` или `container`.

### Шаг 1. Составьте `images_digests.json`

|  |  |
|---|---|
| **Вход** | digest'ы образов, входящих в продукт |
| **Что сделать** | составить JSON-маппинг `имя образа → digest` |
| **Выход** | `images_digests.json` |

```json
{
  "<image>": "sha256:<digest>",
  "<another-image>": "sha256:<digest>"
}
```

Значения должны быть валидными OCI digest'ами (`sha256:<hex>`), иначе merge
упадёт с ошибкой парсинга. Набор образов определяет гранулярность будущего SBOM:
один модуль, срез продукта или весь продукт — решаете вы.

Один из способов получить digest'ы — build-report сборки
(`werf build --save-build-report`), поле `.Images.<image>.DockerImageDigest`.

### Шаг 2. Соберите merged SBOM: `werf sbom merge`

|  |  |
|---|---|
| **Вход** | `images_digests.json` с шага 1 |
| **Команда** | `werf sbom merge --input=... --ispras-format=... --app-name=... --app-version=... --manufacturer=... -o <файл>` |
| **Выход** | единый SBOM в формате ИСПРАС |

```bash
werf sbom merge \
  --input=images_digests.json \
  --ispras-format=container \
  --app-name=<app> \
  --app-version=<version> \
  --manufacturer=<manufacturer> \
  -o merged-sbom.json
```

`sbom merge` скачивает per-image SBOM всех образов из `--input` по digest'ам и
мержит их в единый SBOM по схеме ИСПРАС. Обязательные флаги: `--input`,
`--ispras-format` (`oss` | `container`), `--app-name`, `--app-version`,
`--manufacturer`. Флаг `-o` опционален — без него merged SBOM печатается в stdout.

**Ожидаемый результат:** единый SBOM в выбранном формате ИСПРАС, включающий
компоненты всех образов из `--input`.

### Шаг 3. Провалидируйте: `werf sbom validate`

|  |  |
|---|---|
| **Вход** | merged SBOM с шага 2 (или любой локальный SBOM-файл) |
| **Команда** | `werf sbom validate --path=... --ispras-format=...` |
| **Выход** | результат проверки по схемам ИСПРАС |

```bash
werf sbom validate --path=merged-sbom.json --ispras-format=container
```

**Ожидаемый результат:** валидация завершается успешно (exit code 0). При
несоответствии схеме команда возвращает ошибку с описанием проблемы.
Дополнительно `--check-vcs` проверяет VCS external references; `--path` можно
указать несколько раз, чтобы провалидировать несколько файлов за один запуск.

На этом flow завершён: у вас есть провалидированный merged SBOM продукта.

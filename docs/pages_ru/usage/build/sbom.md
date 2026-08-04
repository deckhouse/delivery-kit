---
title: SBOM
permalink: usage/build/sbom.html
---

> **EXPERIMENTAL:** Сканирование и генерация SBOM-артефактов — экспериментальная возможность. Поведение и параметры конфигурации могут измениться в будущих релизах.

Чтобы включить сканирование и генерацию SBOM артефактов в процессе сборки, необходимо настроить глобальную секцию `build.sbom` и, при необходимости, указать дополнительные компоненты для каждого образа.

Результат сканирования сохраняется исключительно в container registry как OCI-артефакт, прикреплённый к соответствующему образу. **Флаг `--repo` обязателен**: если SBOM включён, но `--repo` не указан, сборка завершается ошибкой:

```
SBOM generation requires a container registry (specify --repo)
```

Локальный образ с суффиксом `-sbom` не создаётся.

## Глобальная конфигурация проекта (`build.sbom`)

Следующие параметры активируют процесс сканирования для всех образов проекта:
1. Установите `build.sbom.enable: true`, чтобы включить функцию.
2. Задайте стандарт вывода через `standard: cyclonedx@1.6` (на данный момент поддерживается только `cyclonedx@1.6`).

```yaml
project: werf-sbom-meta-example
configVersion: 1
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
```

Сейчас данная опция использует следующие _умолчания_:

| Свойство                                  | Значение                                                                                 |
|-------------------------------------------|------------------------------------------------------------------------------------------|
| **Сканер**                                | syft                                                                                     |
| **Образ сканера**                         | anchore/syft:v1.45.1                                                             |
| **Политика получения образа**             | `PullIfMissing`                                                                          |
| **Способ подключения к источнику данных** | daemon + socket via volume (для Docker) |
| **Путь в образе источнике**               | корень OS                                                                                |
| **Настройки сканирования**                | [ссылка](https://github.com/anchore/syft/wiki/Configuration#list-of-configurable-values) |
| **Исходящий стандарт**                    | `CycloneDX@1.6`                                                                          |
| **Исходящий формат**                      | `JSON`                                                                                   |

## Требования к базовому образу

Когда генерация SBOM включена, каждый базовый образ, указанный через `from` или `fromImage`, и каждый образ, указанный через `import`, **должен иметь прикреплённый SBOM-артефакт в registry**. Альтернативы этому требованию нет; единственное исключение описано ниже.

Если образ не имеет прикреплённого SBOM и не несёт метку `io.deckhouse.internal.builder=true`, сборка завершается ошибкой:

```
the base image "example.registry.io/myimage:latest" must either have the label
"io.deckhouse.internal.builder" set to "true" or have an SBOM artifact attached;
to generate an SBOM for the base image, rebuild it with SBOM generation enabled
```

Чтобы устранить ошибку, пересоберите базовый образ с `build.sbom.enable: true`.

Если базовый образ — `scratch`, он создаёт пустой SBOM без компонентов.

**Устаревшее исключение (deprecated).** Два семейства старых сборочных образов Deckhouse несут метку `io.deckhouse.internal.builder=true`, но не имеют прикреплённого SBOM:

- `registry.deckhouse.io/container-factory/builder/golang` (и его теги)
- `registry.deckhouse.io/container-factory/builder/alpine` (и его теги)

Сборки с такими образами пока завершаются успешно, но выдают предупреждение:

```
The builder image "..." is DEPRECATED and it WILL CAUSE AN ERROR in the future.
Plan your migration to an up-to-date builder image.
```

Любой другой образ, несущий метку `io.deckhouse.internal.builder=true`, но не имеющий SBOM, включая более новые образы `container-factory`, завершит сборку ошибкой:

```
the base image "..." must have an SBOM artifact attached;
the image is a builder image but SBOM is required
```

Такие образы нужно пересобрать с `build.sbom.enable: true`, чтобы прикрепить SBOM.

## Свойства безопасности ГОСТ (`sbom.gost`)

Для соответствия стандартам безопасности ГОСТ можно настроить обязательные свойства безопасности для всех компонентов в SBOM. Эти свойства будут внедрены во все прямые компоненты итогового SBOM. По умолчанию как генерируемый, так и определяемый пользователем SBOM-ы обогащаются значениями `attackSurface=yes` и `securityFunction=yes`, если не задано иное через настройки проекта (meta-уровень) или конкретного образа (image-уровень).

1. `attackSurface`: Свойство поверхности атаки (`yes` | `no` | `indirect`).
2. `securityFunction`: Свойство функции безопасности (`yes` | `no` | `indirect`).

Эти свойства можно определить глобально в `build.sbom.gost` или для конкретного образа в `image.sbom.gost`. Конфигурация на уровне образа переопределяет глобальную конфигурацию.

> **ПРИМЕЧАНИЕ:** Интеграция свойств ГОСТ является экспериментальной и строго привязана к стандарту `cyclonedx@1.6`.

Пример:
```yaml
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
    gost:
      attackSurface: yes
      securityFunction: no
```

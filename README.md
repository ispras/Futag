# Оглавление

- [Оглавление](#оглавление)
  - [1. Описание](#1-описание)
  - [2. Установка](#2-установка)
  - [3. Примеры использования](#3-примеры-использования)
  - [4. Сборка из исходного кода](#4-сборка-из-исходного-кода)
  - [5. Авторы](#5-авторы)
  - [6. Статьи](#6-статьи)
  - [7. Найденные ошибки](#7-найденные-ошибки)

## 1. Описание

FUTAG — это автоматизированный инструмент генерации фаззинг-целей для программных библиотек.
В отличие от обычных программ, программная библиотека может не содержать точки входа и не принимать входные данные, поэтому создание вручную фаззинг-цели для анализа программных библиотек остается проблемой и требует ресурсов. Одним из решением данной проблемы является автоматизация процесса создания фаззинг-целей, что уменьшает количество затрачиваемых ресурсов.
FUTAG использует инструменты Clang и Clang LLVM в качестве внешнего интерфейса для анализа библиотек и генерации фаззинг-целей.
FUTAG во время работы использует статический анализ для поиска:
- Зависимостей сущностей (типы данных, функции, структуры и т.д.) в исходном коде целевой библиотеки.
- Контекста использования библиотеки.
Далее информация, полученная по результатам статического анализа, используется для генерации фаззинг-целей.

Данный проект основан на LLVM со статическим анализом Clang, а также LLVM lto и распространяется под лицензией ["GPL v3 license"](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework)

В настоящее время Futag поддерживает:
- автоматическую сборку библиотеки с Makefile, cmake и configure;
- генерацию фаззинг-оберток для функций библиотек языка Си и Си++;

Дополнительно Futag предоставляет возможность тестового запуска скомпилированных целей.

## 2. Установка

Данная инструкция позволяет собрать копию проекта и запустить её в Unix-подобной системе. 

### 2.1. Зависимости

Инструмент FUTAG основан на [LLVM-project](https://llvm.org/). Для компиляции проекта необходимо, чтобы следующие пакеты были установлены в вашей системе:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=7.1.0 C/C++ compiler
- [Python](https://www.python.org/) >=3.8 Automated test suite
- [pip](https://pypi.org/project/pip/) >=22.0.4
- [zlib](http://zlib.net/) >=1.2.3.4 Compression library
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Для получения более детальной информации о зависимостях, необходимых для сборки LLVM, вы можете ознакомиться с документацией по указанной [ссылке](https://llvm.org/docs/GettingStarted.html#requirements)

### 2.2. Установка:

- Скачать последний релиз [futag-llvm.latest.tar.gz](https://github.com/ispras/Futag/releases/tag/latest) и разархивировать

- Установить зависимости: 
```bash
  ~$ pip install -r futag-llvm/python-package/requirements.txt
```

- Установить python-пакет Futag можно по пути futag-llvm/python-package/futag-1.2.tar.gz:
```bash
  ~$ pip install futag-llvm/python-package/futag-1.2.tar.gz
```

## 3. Примеры использования

- Запуск сборки, проверки и анализа

```python
# предварительно должен быть установлен пакет futag-<версия>.tar.gz
from futag.preprocessor import *

testing_lib = Builder(
    "futag-llvm/", # путь к директории "futag-llvm" [2.2.]
    "path/to/library/source/code" # путь к директории содержащей исходные кода исследуемого ПО
)
testing_lib.auto_build()
testing_lib.analyze()
```

- Генерация и компиляция драйверов

```python
# предварительно должен быть установлен пакет futag-<версия>.tar.gz
from futag.generator import *

g = Generator(
    "futag-llvm/", # путь к директории "futag-llvm"
    "path/to/library/source/code" # путь к директории содержащей исходные кода исследуемого ПО
)

# Generate fuzz drivers
g.gen_targets()

# Compile fuzz drivers
g.compile_targets()
```
По-умолчанию, успешно скомпилированные фаззинг-обертки для целевых функций находятся в каталоге futag-fuzz-drivers, где для каждой целевой функции создаётся своя поддиректория название которой совпадает с именем целевой функции. 
Если для функции сгенерировалось несколько фаззинг-оберток, в подкаталоге целевой функции создаются соответствующие директории, где к имени целевой функции добавляется порядковый номер.
Документация Python-пакета находится [по ссылке](https://github.com/ispras/Futag/tree/main/src/python/futag-package)

Подобную информацию о работе Futag можно прочитать [по ссылке](https://github.com/ispras/Futag/blob/main/How-to-work-with-Futag.md)

Шаблон скриптов запуска можно посмотреть [здесь](https://github.com/ispras/Futag/blob/main/src/python/template-script.py)

Был создан [репозиторий](https://github.com/thientc/Futag-tests) для тестирования Futag над библиотеками (json-c, php, FreeImage, и т.д.), можете протестировать с [Докер-контейнером](https://github.com/ispras/Futag/tree/main/product-tests/libraries-test).

## 4. Сборка из исходного кода

- Склонируйте проект:

```bash
  ~$ git clone https://github.com/ispras/Futag
```
- Подготовьте директорию "custom-llvm" запустив скрипт:
```bash
  ~/Futag/custom-llvm$ ./prepare.sh
```
Этот скрипт создает директорию Futag/build и копирует скрипт Futag/custom-llvm/build.sh в неё

- Запустите в "Futag/build" скопированный скрипт:

```bash
  ~/Futag/build$ ./build.sh
```

- В результате инструмент будет установлен в директорию Futag/futag-llvm

Можете попробовать сборку Futag с готовыми [Докер-файлами](https://github.com/ispras/Futag/tree/main/product-tests/build-test) для разных версий ОС Ubuntu.


## 5. Авторы

- [Чан Ти Тхиен](https://github.com/thientc/) (thientc@ispras.ru)
- Курмангалеев Шамиль (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 6. Статьи

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.

## 7. Найденные ошибки

- Крэш в функции [png_convert_from_time_t](https://github.com/glennrp/libpng/issues/362) библиотеки [libpng версии 1.6.37](https://github.com/glennrp/libpng) (подвержен)
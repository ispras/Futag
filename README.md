# Оглавление

- [Оглавление](#оглавление)
  - [1. Описание](#1-описание)
  - [2. Инструкция по сборке](#2-инструкция-по-сборке)
    - [2.1. Зависимости](#21-зависимости)
    - [2.2. Сборка и установка](#22-сборка-и-установка)
  - [3. Примеры использования](#3-примеры-использования)
  - [4. Авторы](#4-авторы)
  - [5. Статьи](#5-статьи)

## 1. Описание

FUTAG — это автоматизированный инструмент генерации фаззинг-целей для программных библиотек.
В отличие от обычных программ, программная библиотека может не содержать точки входа и не принимать входные данные, поэтому создание вручную фаззинг-цели для анализа программных библиотек остается проблемой и требует ресурсов. Одним из решением данной проблемы является автоматизация процесса создания фаззинг-целей, что уменьшает количество затрачиваемых ресурсов.
FUTAG во время работы использует статический анализ для поиска:

- Зависимостей сущностей (типы данных, функции, структуры и т.д.) в исходном коде целевой библиотеки.
- Контекста использования библиотеки.

Далее информация, полученная по результатам статического анализа, используется для генерации фаззинг-целей.

Данный проект основан на LLVM со статическим анализом Clang, а также LLVM lto и распространяется под лицензией ["GPL v3 license"](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework)

- В настоящее время Futag поддерживает генерацию для библиотек языка Си
## 2. Инструкция по сборке

Данная инструкция позволяет собрать копию проекта и запустить её в Unix-подобной системе. FUTAG использует инструменты Clang и Clang LLVM в качестве внешнего интерфейса для анализа библиотек и генерации фаззинг-целей.

### 2.1. Зависимости

Инструмент FUTAG основан на [LLVM-project](https://llvm.org/). Для компиляции проекта необходимо, чтобы следующие пакеты были установлены в вашей системе:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0 C/C++ compiler
- [Python](https://www.python.org/) >=3.6 Automated test suite
- [pip](https://pypi.org/project/pip/)
- [zlib](http://zlib.net/) >=1.2.3.4 Compression library
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Для получения более детальной информации о зависимостях, необходимых для сборки LLVM, вы можете ознакомиться с документацией по указанной [ссылке](https://llvm.org/docs/GettingStarted.html#requirements)

### 2.2. Сборка и установка

#### Установка пользовательского пакета LLVM
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

- В результате инструмент будет установлен в директорию Futag/futag-llvm-package

- Для корректной работы инструмента необходимо также установить в python пакет "futag":

#### Установка пакета Питона Futag:


```bash
  ~$ pip install Futag/src/python/futag-package/dist/futag-1.1.tar.gz
```

## 3. Примеры использования

Использование FUTAG на тестовом примере:

- Запуск сборки, проверки и анализа

```python
# package futag must be already installed
from futag.preprocessor import *

json0_13 = Builder(
    "Futag/futag-llvm-package/", # path to the futag-llvm-package
    "json-c-json-c-0.13.1-20180305" # library root
)
json0_13.auto_build()
json0_13.analyze()
```

- Генерация и компиляция драйверов

```python
# package futag must be already installed
from futag.generator import *

g = Generator(
"/path/to/futag-analysis-result.json", # path to result file of analysis
"Futag/futag-llvm-package/", # path to the futag-llvm-package
"json-c-json-c-0.13.1-20180305" # library root
)

# Generate fuzz drivers
g.gen_targets()

# Compile fuzz drivers
g.compile_targets()
```
- Успешно скомпилированные цели находятся в каталоге futag-fuzz-drivers. Каждый драйвер находится внутри своей поддиректории.

- Фаззить скомпилированные цели

```python
from futag.fuzzer import *
f = Fuzzer("/Futag/futag-llvm-package", 
"json-c-json-c-0.13.1-20180305/futag-fuzz-drivers")
f.fuzz()
```

Подобную информацию можно читать [по ссылке](https://github.com/ispras/Futag/tree/main/src/python/futag-package)

## 4. Авторы

- Thien Tran (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 5. Статьи

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.

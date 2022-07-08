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

## 2. Инструкция по сборке

Данная инструкция позволяет собрать копию проекта и запустить её в Unix-подобной системе. FUTAG использует инструменты Clang и Clang LLVM в качестве внешнего интерфейса для анализа библиотек и генерации фаззинг-целей.

### 2.1. Зависимости

Инструмент FUTAG основан на [LLVM-project](https://llvm.org/). Для компиляции проекта необходимо, чтобы следующие пакеты были установлены в вашей системе:

- [CMake](https://cmake.org/) >=3.13.4 [cmake-3.19.3-Linux-x86_64.sh](https://github.com/Kitware/CMake/releases/download/v3.19.3/cmake-3.19.3-Linux-x86_64.sh) - Makefile/workspace generator
- [GCC](https://gcc.gnu.org/)>=5.1.0 C/C++ compiler1
- [Python](https://www.python.org/) >=3.6 Automated test suite2
- [Zlib](http://zlib.net/) >=1.2.3.4 Compression library3
- [GNU Make](http://savannah.gnu.org/projects/make) 3.79, 3.79.1 Makefile/build processor

Для получения более детальной информации о зависимостях, необходимых для сборки LLVM, вы можете ознакомиться с документацией по указанной [ссылке](https://llvm.org/docs/GettingStarted.html#requirements)

### 2.2. Сборка и установка

- Склонируйте проект с подмодулями LLVM:

  ```bash
  ~$ git clone --recurse-submodules https://github.com/ispras/Futag
  ```

- Создайте директорию для сборки инструмента. Затем скопируйте в неё скрипт build.sh и запустите в ней скопированный скрипт:

  ```bash
  ~/futag$ mkdir build
  ~/futag$ cp build.sh build/ && cd build
  ~/futag/build$ ./build.sh
  ```

- В результате инструмент будет установлен в директорию ../../futag-package

- Для корректной работы инструмента необходимо также установить в python пакет "futag":

 ```bash
  ~$ pip install /path/to/futag-package/python/futag-package/dist/futag-0.1.tar.gz
  ```

## 3. Примеры использования

Использование FUTAG на тестовом примере test/c_examples/multifile_project:

- Запуск проверки

  ```bash
  /path/to/futag-public-package/bin/scan-build -analyzer-config futag.FutagFunctionAnalyzer:report_dir=`pwd`/futag-function-analyzer-reports -enable-checker futag make -j$(nproc)
  ```

- Компиляция статической библиотеки (для получения дополнительной информации проверьте соответствующий Makefile)

  ```bash
  EXTRA_C_FLAGS=-fsanitize=fuzzer-no-link make archive -j$(nproc)
  ```

- Объединение результатов

  ```bash
  cd futag-function-analyzer-reports
  python3 /path/to/futag-public-package/python/tools/analyzer/analypar.py .
  ```

- Генерация и компиляция драйверов

  ```python
  # package futag must be already installed

  from futag.generator import *

  g = Generator(
    "fuzz-drivers", 
    "/path/to/futag-analysis-result.json", 
    "/path/to/multifile_project.a", # path to the compiled archive
    "/path/to/futag/package/", # path to the futag-package
    "/path/to/library/multifile_project/" # library root
  )

  # Generate fuzz drivers
  g.gen_targets()

  # Compile fuzz drivers
  g.compile_targets()
  ```

- Вы можете найти успешно скомпилированные цели в каталоге fuzz-drivers. Каждый драйвер находится внутри своей поддиректории.


Использование FUTAG на примере библиотеки json-c:

- Сборка библиотеки

  ```bash
  cd json-c-sources
  mkdir build && cd build
  CC=<path-to-futag-public-package>/bin/clang ../configure --prefix=`pwd`/install CFLAGS="-fsanitize=fuzzer-no-link -Wno-error=implicit-const-int-float-conversion"
  make -j$(nproc) && make install
  ```

  После этого вы можете найти скомпилированную версию библиотеки здесь: `<path-to-json-c-sources>/build/install/lib/libjson-c.a`

- Очистка и настройка

  ```bash
  make clean
  ../configure --prefix=`pwd`/install
  ```

- Запуск проверки

  ```bash
  <path-to-futag-public-package>/bin/scan-build -analyzer-config futag.FutagFunctionAnalyzer:report_dir=`pwd`/futag-result -enable-checker futag  make -j$(nproc)
  ```

- Объединение результатов

  ```bash
  cd futag-result
  python3 /path/to/futag-public-package/python/tools/analyzer/analypar.py .
  ```

- Генерация и компиляция драйверов

  ```python
  # package futag must be already installed

  from futag.generator import *

  g = Generator(
    "fuzz-drivers", 
    "/path/to/futag-analysis-result.json", 
    "/path/to/libjson-c.a", # path to the compiled archive
    "/path/to/futag/package/", # path to the futag-package
    "/path/to/json-c-root/" # library root
  )

  # Generate fuzz drivers
  g.gen_targets()

  # Compile fuzz drivers
  g.compile_targets()
  ```
- Успешно скомпилированные цели находятся в каталоге fuzz-drivers. Каждый драйвер находится внутри своей поддиректории.

## 4. Авторы

- Thien Tran (thientc@ispras.ru)
- Shamil Kurmangaleev (kursh@ispras.ru)
- Theodor Arsenij Larionov-Trichkin (tlarionov@ispras.ru)

## 5. Статьи

- C. T. Tran and S. Kurmangaleev, ["Futag: Automated fuzz target generator for testing software libraries"](https://ieeexplore.ieee.org/document/9693749) 2021 Ivannikov Memorial Workshop (IVMEM), 2021, pp. 80-85, doi: 10.1109/IVMEM53963.2021.00021.

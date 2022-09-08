# Играть с Futag

## Как Futag собирает вашу тестируемую библиотеку автоматически 

Для того, чтобы создать фаззинг-обертки для функций в библиотеке, Futag запускает статистический анализ во время компиляции данной библиотеки. Этот процесс реализуется автоматически шагами:
1. создать в каталоге исходного кода библиотеки папку futag-build
2. перейти в папку futag-build
3. запустить configure или cmake в папке futag-build с заданными аргументами (install_path, build_ex_params, и т.д.)
4. запустить make в сфере scan-build с чекером futag.FutagFunctionAnalyzer чтобы извлечь зависимости в папку analysis_path
5. очистить собранные файлы
6. запустить make с параметрами flags (по умолчанию: "-fsanitize=address -g -O0 -fprofile-instr-generate -fcoverage-mapping" - AddressSanitizer, debug, without optimization, information generation for coverage) чтобы собрать отладочную информацию и покрытие
7. запустить make install чтобы установить библиотеку в пользовательскую папку.

Есть возможность объединить [4] и [6] но scan-build не собирает с флагами "-fprofile-instr-generate -fcoverage-mapping" соответственно отсутствует информация о покрытии.

## Написать эффективный python-скрипт
Документация python-пакета можно посмотреть [по ссылке](https://github.com/ispras/Futag/tree/main/src/python/futag-package).

Класс Builder принимает следующие параметры:
```python
class Builder:
    """Futag Builder Class"""

    def __init__(self, futag_llvm_package: str, library_root: str, flags: str = COMPILER_FLAGS, clean: bool = False, build_path: str = BUILD_PATH, install_path: str = INSTALL_PATH, analysis_path: str = ANALYSIS_PATH, processes: int =16, build_ex_params=BUILD_EX_PARAMS):
        """
        Parameters
        ----------
        futag_llvm_package: str
            (*required) path to the futag llvm package (with binaries, scripts, etc)
        library_root: str
            (*required) path to the library root
        flags: str
            flags for compiling. Default to "-fsanitize=address -g -O0 -fprofile-instr-generate -fcoverage-mapping"
        clean: bool
            Option for deleting futag folders if they are exist (futag-build, futag-install, futag-analysis)
        build_path: str
            path to the build directory. This directory will be deleted and create again if clean set to True.
        install_path: str
            path to the install directory. Be careful, this directory will be deleted and create again if clean set to True.
        analysis_path: str
            path for saving report of analysis. This directory will be deleted and create again if clean set to True.
        processes: int
            number of processes while building.
        build_ex_params: str
            extra params for building, for example "--with-openssl" for building curl
        """
```
Примерный скрипт сборки библиотеки:
```python
# package futag must be already installed
from futag.preprocessor import *

lib_test = Builder(
    "Futag/futag-llvm-package/", # path to the futag-llvm-package
    "path/to/library/source/code" # library root
)
lib_test.auto_build()
lib_test.analyze()
```
*path/to/library/source/code* можно задавать как ".", "~/", и т.д.

Если вы хотите скомпилировать библиотеку со своим флагами, то задавайте с помощью параметра *flags*.
```python
lib_test = Builder(
    "/path/to/futag-llvm-package/", 
    ".", 
    flags="-g -O0",
)
```

Если вы повторно запускаете Futag в каталоге исходного кода библиотеки, задав параметр *clean=True* вы можете назначить удаление сгенерированных раньше папок futag-build, futag-install и futag-analysis.
```python
lib_test = Builder(
    "/path/to/futag-llvm-package/", 
    ".", 
    flags="-g -O0",
    True, 
)
```

Папку сборки, папку для сохранения результата анализа, папку установки так же можно задавать с помощью следующих параметров:

```python
lib_test = Builder(
    "/path/to/futag-llvm-package/", 
    ".", 
    flags="-g -O0",
    True, 
    "other-build-folder",
    "other-install-folder", 
    "other-analysis-folder",
)
```
Так же можно задавать количество потоков для сборки параметром *processes*:

```python
lib_test = Builder(
    "/path/to/futag-llvm-package/", 
    ".", 
    flags="-g -O0",
    clean=True, 
    "other-build-folder",
    "other-install-folder", 
    "other-analysis-folder",
    8
)
```

Параметр *build_ex_params* полезен в случае нужно добавить дополнительные параметры при сборке. Например, собрать curl с параметром *--without-ssl* или *--with-ssl*

```python
lib_test = Builder(
    "/path/to/futag-llvm-package/", 
    ".", 
    flags="-g -O0",
    True, 
    "other-build-folder",
    "other-install-folder", 
    "other-analysis-folder",
    8,
    "--without-ssl"
)
```

## Как можно реализовать вручную

[TODO: add text ) ]
# Краткое руководство по использованию Futag

## Описание процесса автоматической сборки Futag тестируемой библиотеки

Для создания фаззинг-оберток для функций в библиотеке, Futag запускает статический анализ во время компиляции данной библиотеки. Этот процесс выполняется Futag автоматически и состоит из следующих шагов:
1. в каталоге исходного кода библиотеки создается папка futag-build
2. осуществляется переход в папку futag-build
3. в папке futag-build запускается configure или cmake с заданными аргументами (install_path, build_ex_params, и т.д.)
4. запускается make (в сфере scan-build с чекером futag.FutagFunctionAnalyzer), зависимости извлекаются и сохраняются в папку analysis_path
5. выполняется удаление собранных файлов
6. запускается make с параметрами flags. По умолчанию параметры имеют значение: "-fsanitize=address -g -O0 -fprofile-instr-generate -fcoverage-mapping" - AddressSanitizer, debug, without optimization, information generation for coverage) - в результате сборки с параметрами по умолчанию формируется фаззинг-цель, включающая опции сбора отладочной информации и покрытия.
7. запустить make install чтобы установить библиотеку в пользовательскую папку.

Есть возможность объединить шаги [4] и [6], но scan-build не собирает с флагами "-fprofile-instr-generate -fcoverage-mapping", соответственно в собранной цели будет отсутстовать инструментация, позволяющая собирать информацию о покрытии.

## Как написать python-скрипт работы с Futag
Полную документацию python-модуля в составе Futag можно посмотреть [по ссылке](https://github.com/ispras/Futag/tree/main/src/python/futag-package).

Класс Builder принимает следующие параметры:
```python
class Builder:
    """Futag Builder Class"""

    def __init__(self, futag_llvm_package: str, library_root: str, flags: str = COMPILER_FLAGS, clean: bool = False, build_path: str = BUILD_PATH, install_path: str = INSTALL_PATH, analysis_path: str = ANALYSIS_PATH, processes: int =4, build_ex_params=BUILD_EX_PARAMS):
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
            Option for deleting futag folders if they are exist, default to False (futag-build, futag-install, futag-analysis). 
        build_path: str
            path to the build directory, default to "futag-build". Be careful, this directory will be deleted and create again if clean set to True.
        install_path: str
            path to the install directory, default to "futag-install". Be careful, this directory will be deleted and create again if clean set to True.
        analysis_path: str
            path for saving report of analysis, default to "futag-analysis". Be careful, this directory will be deleted and create again if clean set to True.
        processes: int
            number of processes while building, default to 4.
        build_ex_params: str
            extra params for building, for example "--with-openssl" for building curl
        """
```
Примерный скрипт сборки библиотеки:
```python
# package futag must be already installed
from futag.preprocessor import *

lib_test = Builder(
    "Futag/futag-llvm/", # path to the futag-llvm
    "path/to/library/source/code" # library root
)
lib_test.auto_build()
lib_test.analyze()
```
*path/to/library/source/code* можно задавать как ".", "~/", и т.д.

Если вы хотите скомпилировать библиотеку со своим флагами, вы сможете задать их с помощью параметра *flags*.
```python
lib_test = Builder(
    "/path/to/futag-llvm/", 
    ".", 
    flags="-g -O0",
)
```

Если вы повторно запускаете Futag в каталоге исходного кода библиотеки, задав параметр *clean=True* вы можете принудительно удалить сгенерированные ранее папки futag-build, futag-install и futag-analysis.
```python
lib_test = Builder(
    "/path/to/futag-llvm/", 
    ".", 
    flags="-g -O0",
    True, 
)
```

Папку сборки, папку для сохранения результата анализа, папку установки так же можно задавать с помощью следующих параметров:

```python
lib_test = Builder(
    "/path/to/futag-llvm/", 
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
    "/path/to/futag-llvm/", 
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
    "/path/to/futag-llvm/", 
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

## Как можно интегрировать Futag с библиотекой, собираемой способом, отличным от поддерживаемых на текущий момент

Кроме cmake и configure библиотеки могут быть собраны разными способами: ninja, mach, и т.д..
В этом случае также можно запустить сборку под контролем средства scan-build в составе анализатора Futag, этот процесс состоит из следующих шагов:

1. Подготовить свою библиотеку (с configure и т.д.)
2. Собрать библиотеку под средством scan-build с анализатором Futag

```bash
$ /path/to/futag-llvm/package/bin/scan-build -enable-checker futag.FutagFunctionAnalyzer -analyzer-config futag.FutagFunctionAnalyzer:report_dir=/path/to/analysis/folder <your-build-script>
```

- Если у вас *ninja* можно запустить как:
```bash
$ /path/to/futag-llvm/package/bin/scan-build -enable-checker futag.FutagFunctionAnalyzer -analyzer-config futag.FutagFunctionAnalyzer:report_dir=/path/to/analysis/folder ninja -j4
```
- Если у вас свой скрипт *build-lib.sh* можно запустить как:
```bash
$ /path/to/futag-llvm/package/bin/scan-build -enable-checker futag.FutagFunctionAnalyzer -analyzer-config futag.FutagFunctionAnalyzer:report_dir=/path/to/analysis/folder build-lib.sh
```

3. Запустить анализатор:

```python
# package futag must be already installed
from futag.preprocessor import *

testing_lib = Builder(
    "Futag/futag-llvm/", # path to the futag-llvm
    "path/to/library/source/code", # library root
    "/path/to/analysis/folder"
)
testing_lib.analyze()
```

4. Запустить генератор:

```python
# package futag must be already installed
from futag.generator import *

g = Generator(
"Futag/futag-llvm/", # path to the futag-llvm
"path/to/library/source/code", # library root
"/path/to/analysis/folder/futag-analysis-result.json"#path to the futag-analysis-result.json file
)
g.gen_targets() # Generate fuzz drivers
g.compile_targets() # Compile fuzz drivers
# Краткий обзор работы инструмент Futag

## 1. Что Futag делает?

- Futag пытается генерировать фаззинг-обертки для функций в бибиотеке как в случае отсутствия контекстов использования тестируемой библиотеки, так и при их наличии. На данный момент генерируются 2 формата фаззинг-оберкток LibFuzzer и AFLPlusPlus. 

## 2. Что входит в инструмент Futag?

- Futag включает в себя проекты clang и compiler-rt проекта LLVM (llvm-project). Futag добавил в clang чекеры (checkers), матчеры (matchers) для анализа исходного кода тестируемой библиотеки.

- Кроме того Futag имеет Питон-пакет, который помогает:
    - запустить сборку;
    - установить (в пользовательском директории);
    - собрать результат анализа;
    - генерировать фаззинг-обертки;
    - фаззить и собрать результат фаззинга

## 3. Скрипт запуска

Ниже приведен пример сценария запуска Futag, комментарии объясняют, как работает Futag.

```python
from futag.preprocessor import *
from futag.generator import * 
from futag.fuzzer import * 
from futag.sysmsg import * 

FUTAG_PATH = "/home/futag/Futag-tests/futag-llvm/" # Путь к директории инструмента Futag "futag-llvm" [*]
library_root = "curl-7.85.0" # путь к директории содержащей исходные кода исследуемого ПО [*]

lib_test = Builder( # модуль для запуска сборки и анализа
    FUTAG_PATH, 
    library_root,
    clean=True,     # перед запуска удаляются ли созданные папки инструментом Futag [1]
    processes=16,   # количество потоков при сборке
    build_ex_params="--without-ssl --disable-ldap --disable-ldaps" # дополнительные параметры при сборке библиотеки - данные параметры запускаются на этапе конфигурации библиотеки curl [*]
)
lib_test.auto_build() # инструмент автоматически собирает, устанавливает библиотеку в папки из вышесказанного [1]
lib_test.analyze() # запуск сборки результата анализа в файл futag-analysis-result.json

lib_test = Generator( # модуль для генерации
    FUTAG_PATH,
    library_root,
    target_type=LIBFUZZER, # формат фаззинг-оберток: LIBFUZZER или AFLPLUSPLUS 
)
lib_test.gen_targets() # генерация оберток
lib_test.compile_targets( # функция для компиляции оберток
    16, 
    keep_failed=True, # сохранить ли не скомпилированные обертки
    extra_include="-DHAVE_CONFIG_H", # дополнительные параметры включаются в строку компиляции. Данный параметр включается при сборке curl [*]
    extra_dynamiclink="-lgsasl -lpsl -lbrotlidec -lz -lidn2" # системые библиотеки включаются на этапе линковки. Данные библиотеки включаются при сборке curl [*]
)

consumer_root = "libstorj-1.0.3"
consumber_builder = ConsumerBuilder(
   FUTAG_PATH, # путь к директории "futag-llvm"
   library_root, # путь к директории содержащей исходные кода тестируемой библиотеки
   consumer_root, # путь к директории содержащей исходные кода потребительской программы
  #  clean=True,
  #  processes=16,
)
consumber_builder.auto_build()
consumber_builder.analyze()

context_generator = ContextGenerator(
    FUTAG_PATH, 
    library_root, 
)
context_generator.gen_context() # генерация фаззинг-оберток для контекстов
context_generator.compile_targets( #компиляция сгенерированных фаззинг-оберток
    keep_failed=True,
)

fuzzer = Fuzzer( # модуль для фаззинга
    FUTAG_PATH,
    fuzz_driver_path="curl-7.85.0/futag-fuzz-drivers", # путь к папке, содержащей скомпилированные обертки
    totaltime=10, # время фаззинга одной обертки 
    coverage=True # показывается ли покрытие 
)
fuzzer.fuzz() # функция для запуска фаззинга
```
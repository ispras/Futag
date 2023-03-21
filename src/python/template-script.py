#!/usr/bin/env python3
from futag.preprocessor import *
from futag.generator import * 

test_build = Builder(
"../futag-llvm",        #Путь к рабочей директории futag
"../json-c",                    #Путь к директории исходных текстов исследуемого приложения
flags="-g -O0",                 #Флаги при сборке
clean=True,                           #Очистить каталоги futag-build, futag-install, futag-analysis перед запуском, допустимые значение: (True/False)(Необязательный параметр, по-умолчанию False)
build_path="../json-c/futag-build",        #Путь к директории futag-build (Необязательный параметр)
install_path="../json-c/futag-install",      #Путь к директории futag-install (Необязательный параметр)
analysis_path="../json-c/futag-analysis",     #Путь к директории futag-analysis (Необязательный параметр)
processes=4,                              #Колличество ядер процессора задействующихся при сборке (Необязательный параметр)
build_ex_params="--disable-zip"                 #Дополнительные параметры компилятора (Необязательный параметр)
)

test_build.auto_build()
test_build.analyze()

generator = Generator(
    "../futag-llvm/",
    "json-c",
)
generator.gen_targets()
generator.compile_targets(
    workers=4, 
    keep_failed=True
)


FUTAG_PATH = "/home/futag/Futag/futag-llvm"
library_root = "json-c-json-c-0.16-20220414"

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

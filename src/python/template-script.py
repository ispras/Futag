#!/usr/bin/env python3
from futag.preprocessor import *

lib_test = Builder(
"../futag-llvm-package",        #Путь к рабочей директории futag
"../json-c",                    #Путь к директории исходных текстов исследуемого приложения
True,                           #Очистить каталоги futag-build, futag-install, futag-analysis перед запуском, допустимые значение: (True/False)(Необязательный параметр, по-умолчанию False)
"../json-c/futag-build",        #Путь к директории futag-build (Необязательный параметр)
"../json-c/futag-install",      #Путь к директории futag-install (Необязательный параметр)
"../json-c/futag-analysis",     #Путь к директории futag-analysis (Необязательный параметр)
4,                              #Колличество ядер процессора задействующихся при сборке (Необязательный параметр)
"--disable-zip"                 #Дополнительные параметры компилятора (Необязательный параметр)
)

lib_test.auto_build()
lib_test.analyze()

lib_test = Generator(
    "../futag-llvm-package/",
    "json-c",
    )
lib_test.gen_targets()
lib_test.compile_targets()

print("-- [Futag]: fuzz-drivers are saved in json-c/futag-fuzz-targets!")

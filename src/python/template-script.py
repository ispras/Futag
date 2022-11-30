#!/usr/bin/env python3
from futag.preprocessor import *
from futag.generator import * 

test_build = Builder(
"../futag-llvm",        #Путь к рабочей директории futag
"../json-c",                    #Путь к директории исходных текстов исследуемого приложения
"-g -O0",                 #Флаги при сборке
True,                           #Очистить каталоги futag-build, futag-install, futag-analysis перед запуском, допустимые значение: (True/False)(Необязательный параметр, по-умолчанию False)
"../json-c/futag-build",        #Путь к директории futag-build (Необязательный параметр)
"../json-c/futag-install",      #Путь к директории futag-install (Необязательный параметр)
"../json-c/futag-analysis",     #Путь к директории futag-analysis (Необязательный параметр)
4,                              #Колличество ядер процессора задействующихся при сборке (Необязательный параметр)
"--disable-zip"                 #Дополнительные параметры компилятора (Необязательный параметр)
)

test_build.auto_build()
test_build.analyze()

generator = Generator(
    "../futag-llvm/",
    "json-c",
)
generator.gen_targets()
generator.compile_targets(True, 4)

print("-- [Futag]: fuzz-drivers are saved in json-c/futag-fuzz-targets!")

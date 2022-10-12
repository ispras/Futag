# Futag build analysis
This is a plugin for analyzing building process
The plugin can be executed like this:
```bash
$ clang -Xclang -add-plugin -Xclang build-analysis -fplugin=/path/to/futag-analysis/build/lib/BuildAnalysis.so simple_example.c
```
To add plugin while configuring the project:
```bash
../configure --with-openssl CFLAGS="-Xclang -add-plugin -Xclang build-analysis -fplugin=/path/to/futag-analysis/build/lib/BuildAnalysis.so" CC=/path/to/futag-analysis/build/bin/clang
```
```bash
cmake -DCMAKE_C_FLAGS="-Xclang -add-plugin -Xclang build-analysis -fplugin=/path/to/futag-analysis/build/lib/BuildAnalysis.so" -DCMAKE_C_COMPILER=/path/to/futag-analysis/build/bin/clang ..
```
# Integrate Fuzz-introspector with Futag

TODO: Change requirement to python 3.8
require xz

[Fuzz-introspector repository](https://github.com/ossf/fuzz-introspector)
```python
pip install -r fuzz-introspector/requirements.txt
```

## Build binutils
apt install texinfo
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir build
cd ./build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make all-gold
cd ../


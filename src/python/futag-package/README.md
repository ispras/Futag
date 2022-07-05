# Python package of Futag

## 1. Install

```bash 
pip install dist/futag-0.1.tar.gz
```

## 2. Usage

```python
>>> from futag.generator import * 
>>> g = Generator("output", "/home/thien/Ubuntu-pkgs/libjson-c-dev/json-c-0.11/build/futag-analysis-result.json")
>>> g.gen_targets()
```
The fuzz-drivers of libjson will be created in folder output.
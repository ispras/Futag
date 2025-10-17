# Futag Workshop

## 1. Introduction

- [Slide: Раскрытие секрета инструмента Futag.pptx](./Раскрытие%20секрета%20инструмента%20Futag.pptx)

## 2. An ease way of automatic testing

- Some useful examples of using Futag to test your library: https://github.com/thientc/Futag-tests

- Steps to use Futag to test your library on Ubuntu 24.04:
  - Download Futag package from github (https://github.com/ispras/Futag/releases)
  - Install dependencies, for example:
```bash
apt install -y apt-utils libncurses5 gcc gcc-multilib binutils binutils-gold binutils-dev g++ make gdb openssh-client git wget xz-utils python3 python3-pip python-is-python3  nano cmake libtool
RUN useradd -ms /bin/bash futag
```
  - Install Futag python-package https://github.com/ispras/Futag/releases (It's better to use virtualenv)
  - Download and extract you library
  - Create [test script](./json-c/futag.all-in-one.py)
  - Run the test, have a cup of coffee and wait for the result
- Example of fuzz target 1:
```c
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "config.h"
#include "math_compat.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include "debug.h"
#include "json_inttypes.h"
#include "json_object.h"
#include "json_object_private.h"
#include "json_tokener.h"
#include "json_util.h"
#include "strdup_compat.h"
#include <locale.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){
    FuzzedDataProvider provider(Fuzz_Data, Fuzz_Size);

    //GEN_BUILTIN
    auto b_1_depth = provider.ConsumeIntegral<int>();
    //GEN_VAR_FUNCTION
    struct json_tokener * s__tok = json_tokener_new_ex(b_1_depth);
    //GEN_CSTRING
    std::string  str_str_fdp = provider.ConsumeRandomLengthString();
    const char * str_str = str_str_fdp.c_str();

    //GEN_SIZE
    int sz_len = static_cast<int >(str_str_fdp.length());

    //FUNCTION_CALL
    json_tokener_parse_ex(s__tok ,str_str ,sz_len );
    //FREE
    return 0;
}
// Compile database:
/*
command: /root/json-c/../futag-llvm/bin/clang -D_GNU_SOURCE -Djson_c_EXPORTS -I/root/json-c/json-c-json-c-0.18-20240915 -I/root/json-c/json-c-json-c-0.18-20240915/.futag-build -g -O0 -fsanitize=address -fprofile-instr-generate -fcoverage-mapping  -ffunction-sections -fdata-sections -Werror -Wall -Wcast-qual -Wno-error=deprecated-declarations -Wextra -Wwrite-strings -Wno-unused-parameter -Wstrict-prototypes -g -fPIC   -D JSON_C_DLL -D_REENTRANT -o CMakeFiles/json-c.dir/json_tokener.c.o -c /root/json-c/json-c-json-c-0.18-20240915/json_tokener.c
location: /root/json-c/json-c-json-c-0.18-20240915/.futag-build
file: /root/json-c/json-c-json-c-0.18-20240915/json_tokener.c
*/

// Compile command:
/*
/root/json-c/../futag-llvm/bin/clang++ -fsanitize=address,fuzzer -fprofile-instr-generate -fcoverage-mapping  -g -O0 -ferror-limit=1 -I/root/json-c/json-c-json-c-0.18-20240915 -I/root/json-c -I/root/json-c/json-c-json-c-0.18-20240915/.futag-build  /root/json-c/json-c-json-c-0.18-20240915/futag-fuzz-drivers/succeeded/json_tokener_parse_ex/json_tokener_parse_ex.1/json_tokener_parse_ex.1.c -o /root/json-c/json-c-json-c-0.18-20240915/futag-fuzz-drivers/succeeded/json_tokener_parse_ex/json_tokener_parse_ex.1/json_tokener_parse_ex.1.out -Wl,--start-group /root/json-c/json-c-json-c-0.18-20240915/.futag-build/libjson-c.a /root/json-c/json-c-json-c-0.18-20240915/.futag-install/lib/libjson-c.a -Wl,--end-group
 */
```

- An easy way to include:
```c
#include"json.h"
```

## 3. Let's helf Futag to understand your library 

- Install dependencies
```bash
apt-get install -y make gdb binutils python3 git gcc cmake wget texinfo automake autoconf bash-completion  gcc-c++* gcc-common python3-module-pip openssh-clients xz binutils-devel
```
- Download and extract Futag package from github
- Install dependencies for libvirt

```bash
apt-get install -y   libudev-devel   libyajl-devel   sanlock-devel  libpcap-devel  libnl-devel  libselinux-devel  libsasl2-devel  polkit  util-linux  qemu-img  lvm2  libparted-devel parted libuuid-devel dmsetup ceph-devel  open-iscsi  libiscsi-devel  libdevmapper-devel  libglusterfs-devel  libnuma-devel   libcap-ng-devel  libcurl-devel   libaudit-devel  libfuse-devel   libnbd-devel  pm-utils  glib2-devel wireshark tshark wireshark-devel  libblkid-devel  libgcrypt-devel libgnutls-devel libp11-kit-devel  libreadline-devel  libtasn1-devel  libattr-devel attr  libacl-devel  glib2-devel  libgio-devel  libxml2-devel xml-utils xsltproc  python3 python3-devel python3-module-pytest  python3-module-docutils  zlib-devel  iproute2  dmidecode  libtirpc-devel  glibc-utils  kmod  mdevctl udev
```
- Download libvirt source code
```bash
git clone git://git.altlinux.org/gears/l/libvirt.git
git checkout 10.7.0-alt1
```

- How to build libvirt:
```bash
gear-rpm -bc
```

- How to use Futag to analyze libvirt:
```bash
~/Futag/futag-llvm/bin/scan-build  -enable-checker futag.FutagAnalyzer -analyzer-config futag.FutagAnalyzer:report_dir=/home/thientc/libvirt/analysis_result gear-rpm -bc
 ```

- How to speed up the analysis:
```bash
~/Futag/futag-llvm/bin/scan-build  -disable-checker core -disable-checker security -disable-checker unix -disable-checker deadcode -disable-checker nullability -disable-checker cplusplus -enable-checker futag.FutagAnalyzer -analyzer-config futag.FutagAnalyzer:report_dir=/home/thientc/libvirt/analysis_result gear-rpm -bc
```
- It's able to replace `gear-rpm -bc` by `./build.sh`

- Specify the output folder `-analyzer-config futag.FutagAnalyzer:report_dir=futag-analysis`:
```bash
~/Futag/futag-llvm/bin/scan-build -disable-checker core -disable-checker security -disable-checker unix -disable-checker deadcode -disable-checker nullability -disable-checker cplusplus -enable-checker futag.FutagAnalyzer -analyzer-config futag.FutagAnalyzer:report_dir=futag-analysis gear-rpm -bc
```

- Analyze the aresult:
```bash
python3 futag.analysis.py
```

- Generate the fuzzing drivers:
```bash
python3 futag.generate.py
```

- Fuzzing the generated fuzzing drivers:
```bash
python3 futag.fuzzing.py
```

- Example of compile commands:
```bash
clang -fsanitize=address,fuzzer -g -O0 -I/var/libvirt/install/libvirt/ -I/var/libvirt/../src/util -I/usr/include/libnl3 -I/usr/lib64/glib-2.0/include -I/var/libvirt/src/util/libvirt_util.a.p -I/var/libvirt -I/var/libvirt/../src -I/var/libvirt/.. -I/usr/include/gio-unix-2.0 -I/usr/include/glib-2.0 -I/var/libvirt/src/util -I/usr/include/yajl -I/var/libvirt/../include -I/usr/include/libxml2 -I/var/libvirt/include -I/var/libvirt/src -I/usr/include/p11-kit-1  /home/thientc/libvirt/futag-fuzz-drivers/failed/virNVMeDeviceListCount/virNVMeDeviceListCount.1/virNVMeDeviceListCount.1.c -o /home/thientc/libvirt/futag-fuzz-drivers/failed/virNVMeDeviceListCount/virNVMeDeviceListCount.1/virNVMeDeviceListCount.1.out -lvirt
```

- Example of fuzz target 1:
```c
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include "virscsivhost.h"
#include "virlog.h"
#include "virfile.h"
#include "viralloc.h"

int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){
    if (Fuzz_Size < 1 * sizeof(char)) return 0;
    size_t dyn_cstring_buffer = (size_t) (Fuzz_Size + 1*sizeof(char) - (1 * sizeof(char) ));
    //generate random array of dynamic string sizes
    size_t dyn_cstring_size[1];
    dyn_cstring_size[0] = dyn_cstring_buffer;
    //end of generation random array of dynamic string sizes
    uint8_t * futag_pos = Fuzz_Data;
    
    //GEN_VAR_FUNCTION
    virSCSIVHostDeviceList * s__list = virSCSIVHostDeviceListNew();
    
    //GEN_CSTRING1
    char * rstr_2_name0 = (char *) malloc((dyn_cstring_size[0] + 1)* sizeof(char));
    memset(rstr_2_name0, 0, dyn_cstring_size[0] + 1);
    memcpy(rstr_2_name0, futag_pos, dyn_cstring_size[0]);
    futag_pos += dyn_cstring_size[0];
    const char * str_2_name0 = rstr_2_name0;
    //GEN_VAR_FUNCTION
    virSCSIVHostDevice * s__dev = virSCSIVHostDeviceNew(str_2_name0);
    //FUNCTION_CALL
    virSCSIVHostDeviceListFind(s__list ,s__dev );
    //FREE
    if (rstr_2_name0) {
        free(rstr_2_name0);
        rstr_2_name0 = NULL;
    }
    return 0;
}
// Compile command:
/* 
clang -fsanitize=address,fuzzer -g -O0 -I/var/libvirt/src/util -I/var/libvirt -I/var/libvirt/../include -I/var/libvirt/include -I/usr/include/glib-2.0 -I/var/libvirt/src/util/libvirt_util.a.p -I/usr/include/yajl -I/var/libvirt/../src/util -I/var/libvirt/src -I/var/libvirt/../src -I/usr/include/gio-unix-2.0 -I/usr/include/libxml2 -I/var/libvirt/.. -I/usr/include/libnl3 -I/usr/include/p11-kit-1 -I/usr/lib64/glib-2.0/include  /home/thientc/libvirt/futag-fuzz-drivers/succeeded/virSCSIVHostDeviceListFind/virSCSIVHostDeviceListFind.1/virSCSIVHostDeviceListFind.1.c -o /home/thientc/libvirt/futag-fuzz-drivers/succeeded/virSCSIVHostDeviceListFind/virSCSIVHostDeviceListFind.1/virSCSIVHostDeviceListFind.1.out -lvirt
 */

```
- Example of fuzz target 2:
```c
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "virnvme.h"
#include "viralloc.h"
#include "virlog.h"

int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){
    if (Fuzz_Size < 1 * sizeof(char) + sizeof(unsigned long) + sizeof(_Bool)) return 0;
    size_t dyn_cstring_buffer = (size_t) (Fuzz_Size + 1*sizeof(char) - (1 * sizeof(char) + sizeof(unsigned long) + sizeof(_Bool) ));
    //generate random array of dynamic string sizes
    size_t dyn_cstring_size[1];
    dyn_cstring_size[0] = dyn_cstring_buffer;
    //end of generation random array of dynamic string sizes
    uint8_t * futag_pos = Fuzz_Data;
    
    //GEN_CSTRING1
    char * rstr_1_device_link0 = (char *) malloc((dyn_cstring_size[0] + 1)* sizeof(char));
    memset(rstr_1_device_link0, 0, dyn_cstring_size[0] + 1);
    memcpy(rstr_1_device_link0, futag_pos, dyn_cstring_size[0]);
    futag_pos += dyn_cstring_size[0];
    const char * str_1_device_link0 = rstr_1_device_link0;
    //GEN_VAR_FUNCTION
    virPCIDeviceAddress * s__address = virPCIGetDeviceAddressFromSysfsLink(str_1_device_link0);
    //GEN_BUILTIN
    unsigned long b_namespace;
    memcpy(&b_namespace, futag_pos, sizeof(unsigned long));
    futag_pos += sizeof(unsigned long);
    
    //GEN_BUILTIN
    _Bool b_managed;
    memcpy(&b_managed, futag_pos, sizeof(_Bool));
    futag_pos += sizeof(_Bool);
    
    //FUNCTION_CALL
    virNVMeDeviceNew(s__address ,b_namespace ,b_managed );
    //FREE
    if (rstr_1_device_link0) {
        free(rstr_1_device_link0);
        rstr_1_device_link0 = NULL;
    }
    return 0;
}
// Compile command:
/* 
clang -fsanitize=address,fuzzer -g -O0 -I/var/libvirt/.. -I/var/libvirt/../src -I/usr/include/gio-unix-2.0 -I/var/libvirt/src -I/usr/include/glib-2.0 -I/usr/include/libnl3 -I/var/libvirt/../include -I/usr/lib64/glib-2.0/include -I/usr/include/p11-kit-1 -I/var/libvirt/src/util/libvirt_util.a.p -I/var/libvirt -I/usr/include/yajl -I/usr/include/libxml2 -I/var/libvirt/include -I/var/libvirt/../src/util -I/var/libvirt/src/util  /home/thientc/libvirt/futag-fuzz-drivers/succeeded/virNVMeDeviceNew/virNVMeDeviceNew.3/virNVMeDeviceNew.3.c -o /home/thientc/libvirt/futag-fuzz-drivers/succeeded/virNVMeDeviceNew/virNVMeDeviceNew.3/virNVMeDeviceNew.3.out -lvirt
 */
```
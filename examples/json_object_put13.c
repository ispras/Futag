#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "config.h"
#include "strerror_override.h"
#include <assert.h>
#include <limits.h>
#include <math.h>
#include "arraylist.h"
#include "debug.h"
#include "json_object_private.h"
#include "json_util.h"
#include "linkhash.h"
#include "math_compat.h"
#include "snprintf_compat.h"
#include "strdup_compat.h"

int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){
    if (Fuzz_Size < 3 + 0 + sizeof(int64_t)+sizeof(int64_t)+sizeof(int32_t)) return 0;
    size_t dyn_buffer = (size_t) ((Fuzz_Size - ( 0 + 3 + sizeof(int64_t)+sizeof(int64_t)+sizeof(int32_t))));
    //generate random array of dynamic string sizes
    size_t dyn_size[3];
    srand(time(NULL));
    if(dyn_buffer == 0) dyn_size[0] = dyn_buffer; 
    else dyn_size[0] = rand() % dyn_buffer; 
    size_t remain = dyn_size[0];
    for(size_t i = 1; i< 3 - 1; i++){
        if(dyn_buffer - remain == 0) dyn_size[i] = dyn_buffer - remain;
        else dyn_size[i] = rand() % (dyn_buffer - remain);
        remain += dyn_size[i];
    }
    dyn_size[3 - 1] = dyn_buffer - remain;
    //end of generation random array of dynamic string sizes
    uint8_t * pos = Fuzz_Data;
    struct json_object * body = json_object_new_object();
    //GEN_CSTRING
    char * rstr_s0 = (char *) malloc(dyn_size[0] + 1);
    memset(rstr_s0, 0, dyn_size[0] + 1);
    memcpy(rstr_s0, pos, dyn_size[0] );
    pos += dyn_size[0];
    const char * str_s0 = rstr_s0;
    
    struct json_object * FutagRefVarRVL = json_object_new_string(str_s0 );
    //FREE
    if (rstr_s0) {
        free(rstr_s0);
        rstr_s0 = NULL;
    }
    //GEN_CSTRING
    char * rstr_s1 = (char *) malloc(dyn_size[1] + 1);
    memset(rstr_s1, 0, dyn_size[1] + 1);
    memcpy(rstr_s1, pos, dyn_size[1] );
    pos += dyn_size[1];
    const char * str_s1 = rstr_s1;
    
    struct json_object * FutagRefVarU7m = json_object_new_string(str_s1 );
    //FREE
    if (rstr_s1) {
        free(rstr_s1);
        rstr_s1 = NULL;
    }
    //GEN_BUILTIN
    int64_t b_i2;
    memcpy(&b_i2, pos, sizeof(int64_t));
    pos += sizeof(int64_t);
    
    struct json_object * FutagRefVarBtH = json_object_new_int64(b_i2 );
    //GEN_BUILTIN
    int64_t b_i3;
    memcpy(&b_i3, pos, sizeof(int64_t));
    pos += sizeof(int64_t);
    
    struct json_object * FutagRefVaraBY = json_object_new_int64(b_i3 );
    //GEN_BUILTIN
    int32_t b_i4;
    memcpy(&b_i4, pos, sizeof(int32_t));
    pos += sizeof(int32_t);
    
    struct json_object * FutagRefVarYNd = json_object_new_int(b_i4 );
    //GEN_CSTRING
    char * rstr_s5 = (char *) malloc(dyn_size[2] + 1);
    memset(rstr_s5, 0, dyn_size[2] + 1);
    memcpy(rstr_s5, pos, dyn_size[2] );
    pos += dyn_size[2];
    const char * str_s5 = rstr_s5;
    
    struct json_object * FutagRefVaruMn = json_object_new_string(str_s5 );
    //FREE
    if (rstr_s5) {
        free(rstr_s5);
        rstr_s5 = NULL;
    }
    const char * key7 = "dataHash";
    //FUNCTION_CALL
    json_object_object_add(body ,key7 ,FutagRefVarRVL );
    const char * key10 = "token";
    //FUNCTION_CALL
    json_object_object_add(body ,key10 ,FutagRefVarU7m );
    const char * key13 = "exchangeStart";
    //FUNCTION_CALL
    json_object_object_add(body ,key13 ,FutagRefVarBtH );
    const char * key16 = "exchangeEnd";
    //FUNCTION_CALL
    json_object_object_add(body ,key16 ,FutagRefVaraBY );
    const char * key19 = "exchangeResultCode";
    //FUNCTION_CALL
    json_object_object_add(body ,key19 ,FutagRefVarYNd );
    const char * key22 = "exchangeResultMessage";
    //FUNCTION_CALL
    json_object_object_add(body ,key22 ,FutagRefVaruMn );
    //FUNCTION_CALL
    json_object_put(body );
    return 0;
}
// Compile database: 
/*
command: cc -c -D_GNU_SOURCE -Djson_c_EXPORTS -I/home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414 -I/home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/.futag-build -g -O0 -fsanitize=address -ffunction-sections -fdata-sections -Werror -Wall -Wcast-qual -Wno-error=deprecated-declarations -Wextra -Wwrite-strings -Wno-unused-parameter -Wstrict-prototypes -g -fPIC -D JSON_C_DLL -D_REENTRANT -o CMakeFiles/json-c.dir/json_object.c.o /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/json_object.c
location: /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/.futag-build
file: /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/json_object.c
*/

// Compile command:
/* 
/home/futag/Futag/futag-llvm/bin/clang -fsanitize=address,fuzzer -g -O0 -ferror-limit=1 -I/home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/ -I/home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/.futag-build/  /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/futag-context-fuzz-drivers/succeeded/json_object_put/json_object_put13/json_object_put13.c -o /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/futag-context-fuzz-drivers/succeeded/json_object_put/json_object_put13/json_object_put13.out -Wl,--start-group /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/.futag-build/libjson-c.a /home/futag/Futag-tests/json-c/json-c-json-c-0.16-20220414/.futag-install/lib/libjson-c.a -Wl,--end-group 
 */

// Error log:
/* 

 */

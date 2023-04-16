#define VAR_ARRAYS 1
#define USE_ALLOCA 1
#define NONTHREADSAFE_PSEUDOSTACK 1
#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "celt.h"
#include "opus.h"
#include "modes.h"
#include "API.h"
#include "stack_alloc.h"
#include "float_cast.h"
#include "opus_private.h"
#include "os_support.h"
#include "structs.h"
#include "mathops.h"
#include "config.h"
#include "opus_projection.h"
#include "mapping_matrix.h"

int LLVMFuzzerTestOneInput(uint8_t * Fuzz_Data, size_t Fuzz_Size){
    if (Fuzz_Size < 0*sizeof(wchar_t) + 0*sizeof(char) + 1 + 0 + sizeof(opus_int32) + sizeof(int) + sizeof(int) + sizeof(opus_int32) + sizeof(opus_int16) + sizeof(int) + sizeof(int)) return 0;
    size_t dyn_cstring_buffer = (size_t) ((Fuzz_Size + sizeof(char) - (0*sizeof(wchar_t) + 0*sizeof(char) + 1 + 0 + sizeof(opus_int32) + sizeof(int) + sizeof(int) + sizeof(opus_int32) + sizeof(opus_int16) + sizeof(int) + sizeof(int) )));
    //generate random array of dynamic string sizes
    size_t dyn_cstring_size[1];
    dyn_cstring_size[0] = dyn_cstring_buffer;
    //end of generation random array of dynamic string sizes
    uint8_t * futag_pos = Fuzz_Data;
    
    //GEN_BUILTIN
    opus_int32 b_1_Fs;
    memcpy(&b_1_Fs, futag_pos, sizeof(opus_int32));
    futag_pos += sizeof(opus_int32);
    //GEN_BUILTIN
    int b_1_channels;
    memcpy(&b_1_channels, futag_pos, sizeof(int));
    futag_pos += sizeof(int);
    //GEN_BUILTIN
    int b__1_error;
    memcpy(&b__1_error, futag_pos, sizeof(int));
    futag_pos += sizeof(int);
    //GEN_POINTER
    int * p_b__1_error = & b__1_error;
    //GEN_VAR_FUNCTION
    OpusDecoder * s__st = opus_decoder_create(b_1_Fs,b_1_channels,p_b__1_error);
    //GEN_CSTRING
    unsigned char * rstr_data = (unsigned char *) malloc((dyn_cstring_size[0] + 1)* sizeof(char));
    memset(rstr_data, 0, dyn_cstring_size[0] + 1);
    memcpy(rstr_data, futag_pos, dyn_cstring_size[0]);
    futag_pos += dyn_cstring_size[0];
    const unsigned char * str_data = rstr_data;
    
    //GEN_BUILTIN
    opus_int32 b_len;
    memcpy(&b_len, futag_pos, sizeof(opus_int32));
    futag_pos += sizeof(opus_int32);
    
    //GEN_BUILTIN
    opus_int16 b__pcm;
    memcpy(&b__pcm, futag_pos, sizeof(opus_int16));
    futag_pos += sizeof(opus_int16);
    //GEN_POINTER
    opus_int16 * p_b__pcm = & b__pcm;
    
    //GEN_BUILTIN
    int b_frame_size;
    memcpy(&b_frame_size, futag_pos, sizeof(int));
    futag_pos += sizeof(int);
    
    //GEN_BUILTIN
    int b_decode_fec;
    memcpy(&b_decode_fec, futag_pos, sizeof(int));
    futag_pos += sizeof(int);
    
    //FUNCTION_CALL
    opus_decode(s__st ,str_data ,b_len ,p_b__pcm ,b_frame_size ,b_decode_fec );
    //FREE
    if (rstr_data) {
        free(rstr_data);
        rstr_data = NULL;
    }
    return 0;
}
// Compile database: 
/*
command: cc -c -DHAVE_CONFIG_H -I. -I/home/futag/Futag-tests/libopus/opus-1.3.1 -I/home/futag/Futag-tests/libopus/opus-1.3.1/include -I/home/futag/Futag-tests/libopus/opus-1.3.1/celt -I/home/futag/Futag-tests/libopus/opus-1.3.1/silk -I/home/futag/Futag-tests/libopus/opus-1.3.1/silk/float -I/home/futag/Futag-tests/libopus/opus-1.3.1/silk/fixed -g -O0 -fsanitize=address -g -O0 -fsanitize=address -fPIC -DPIC -o src/.libs/opus_decoder.o /home/futag/Futag-tests/libopus/opus-1.3.1/src/opus_decoder.c
location: /home/futag/Futag-tests/libopus/opus-1.3.1/.futag-build
file: /home/futag/Futag-tests/libopus/opus-1.3.1/src/opus_decoder.c
*/

// Compile command:
/* 
/home/futag/Futag-tests/futag-llvm/bin/clang -fsanitize=address,fuzzer -g -O0 -ferror-limit=1 -I/home/futag/Futag-tests/libopus/opus-1.3.1/.futag-build/ -I/home/futag/Futag-tests/libopus/opus-1.3.1/ -I/home/futag/Futag-tests/libopus/opus-1.3.1/include/ -I/home/futag/Futag-tests/libopus/opus-1.3.1/celt/ -I/home/futag/Futag-tests/libopus/opus-1.3.1/silk/ -I/home/futag/Futag-tests/libopus/opus-1.3.1/silk/float/ -I/home/futag/Futag-tests/libopus/opus-1.3.1/silk/fixed/ -DHAVE_CONFIG_H -I/home/futag/Futag-tests/libopus/opus-1.3.1/src/ /home/futag/Futag-tests/libopus/opus-1.3.1/futag-fuzz-drivers/succeeded/opus_decode/opus_decode1/opus_decode1.c -o /home/futag/Futag-tests/libopus/opus-1.3.1/futag-fuzz-drivers/succeeded/opus_decode/opus_decode1/opus_decode1.out -Wl,--start-group /home/futag/Futag-tests/libopus/opus-1.3.1/.futag-build/.libs/libopus.a /home/futag/Futag-tests/libopus/opus-1.3.1/.futag-install/lib/libopus.a -Wl,--end-group 
 */

// Error log:
/* 
/home/futag/Futag-tests/libopus/opus-1.3.1/.futag-fuzz-drivers/opus_decode/opus_decode1/opus_decode1.c:80:5: warning: ignoring return value of function declared with 'warn_unused_result' attribute [-Wunused-result]
    opus_decode(s__st ,str_data ,b_len ,p_b__pcm ,b_frame_size ,b_decode_fec );
    ^~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 warning generated.

 */

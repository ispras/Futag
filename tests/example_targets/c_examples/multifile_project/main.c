#include "mul_div.h"
#include "add_sub.h"

#include <stdio.h>

int main(int argc, char* argv[]) {
    double res1 = Mul(12, 13);
    double res2 = Add(res1, 1506.0f);
    double res3 = Sub(51, res2);

    printf("Result: %f\n", res3);

    return 0;
}

#include "mul_div.h"
#include <string.h>

double Mul(double a, double b) {
    return a * b;
}

double Div(double a, double b) {
    return a / b;
}

int DummyFunc(double a, char* str) {
    if (strlen(str) >= 4) {
        if (str[0] == 'F') {
            if (str[1] == 'U') {
                if (str[2] == 'Z') {
                    if (str[3] == 'Z') {
                        return ((int)a / 0);
                    }
                }
            }
        }
    }

    return 0;
}
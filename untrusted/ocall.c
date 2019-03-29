#include "ocall.h"
#include <stdio.h>      /* vsnprintf */

void ocall_myenclave_sample(const char *str)
{
    /* Prox/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

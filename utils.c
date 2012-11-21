#include <stdio.h>
#include <stdlib.h>
#include "log.h"

void _Assert (char* name, char* strFile, unsigned uLine) 
{           
    dump(L_ERR, "Assertion failed: %s, %s, line %u", name, strFile, uLine);
    abort();
}          

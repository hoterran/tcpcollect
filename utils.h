#ifndef _UTILS_H_

#define _UTILS_H_

#ifdef DEBUG
#define ASSERT(f) do {if(f) ((void)0); else _Assert(#f, __FILE__, __LINE__);} while(0)
#else
#define ASSERT(f) ((void)0)
#endif
 
void _Assert(char*, char*, unsigned);   

#endif

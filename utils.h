#ifndef _UTILS_H_
#define _UTILS_H_

#ifdef DEBUG
#define ASSERT(f) do {if(f) ((void)0); else _Assert(#f, __FILE__, __LINE__);} while(0)
#else
#define ASSERT(f) ((void)0)
#endif
 
void _Assert(char*, char*, unsigned);   
int daemon_init(void) ;

int single_process(char *process_name);

void sig_init(void);

#define OK      (0)
#define ERR     (-1)
#define PEND    (1)

typedef unsigned short uint16;
typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long ulong;

#endif

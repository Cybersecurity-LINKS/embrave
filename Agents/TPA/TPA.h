#ifndef TPA_H
#define TPA_H

#include <stdint.h> 
#include <stdio.h>

#define HANDLE_EK 0x81000003
#define HANDLE_AK 0x81000004 

#define HANDLE_SIZE 11



int TPA_init(void);

#endif
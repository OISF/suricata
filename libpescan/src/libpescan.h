/*
libpescan.h

Libpescan provides identification of anomalous characteristics of portable executables

Copyright (C) 2012 BAE Systems Information Solutions Inc.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#ifndef _LIBPESCAN_H__
#define _LIBPESCAN_H__
#include <time.h>

#define PE_NOT_PE              0
#define PE_TRUNCATED          -1
#define PE_IFH_NOT3264        -2
#define PE_IFH_NOT_BINARY     -3
#define PE_OH_BAD_MAGIC       -4
#define PE_BAD_DATA           -5
#define PE_INDETERMINATE      -6
#define PE_TRACKING        -1024

#define PE_EXE  1
#define PE_DLL  2
#define PE_SYS  4

#define PE_32   8
#define PE_64  16

#define MAX_PE_SECTIONS 256

typedef enum {
    EXEC_AND_WRITE,
    EXEC_NOT_CODE,
    NON_PRINT_NAME,
    NO_EXEC_BIT,
    BAD_CODE_SUM,
    BAD_DATA_SUM,
    BAD_UDATA_SUM,
    ENTRY_NO_EXEC,
    ENTRY_NO_CODE,
    FV_MAX,

} phad_anomalies;

typedef struct {
    unsigned char name[8];
    unsigned virt_rva;
    unsigned virt_size;
    unsigned raw_size;
    unsigned raw_offset;
    unsigned cx; // characteristics;
} pesection_t;

typedef struct {
    unsigned tls_rva;
    unsigned tls_size;
    time_t date;
    int status;
    int mzoffset;
    int peoffset;
    unsigned tstamp;
    unsigned chksum;
    unsigned machine; // i386, AMD
    int petype; // WinPE=>EXE/DLL/SYS
    int nsections;
    int size_of_image;
    int opt_hdr_size;
    int pesize;
    int link_major;
    int link_minor;
    int os_major;
    int os_minor;
    int size_of_code;
    int size_of_data;
    int size_of_udata;
    unsigned entryptr;
    unsigned base_of_code;
    unsigned size_of_hdrs;
    unsigned image_base;
    unsigned sect_align;
    unsigned file_align;
    unsigned subsystem;
    int nrva;
    unsigned export_rva;
    unsigned export_size;
    unsigned import_rva;
    unsigned import_size;
    unsigned rsrc_rva;
    unsigned rsrc_size;
    unsigned isize;
    int trunc;
    pesection_t sx[MAX_PE_SECTIONS];
    int fv[FV_MAX];
    unsigned fvflags;
    int fvflagcnt;
    double pescore;
} peattrib_t;

void   fvinit( peattrib_t * wp );
void   fvset( peattrib_t * wp, int index, int value );
void   fvadd( peattrib_t * wp, int index, int value );
int    pescan( peattrib_t * wp, unsigned char * buf, int nbuf, int debug );
double pescore( peattrib_t * wp );
int bad_sect_name( char *s );

#endif  //_LIBPESCAN_H__

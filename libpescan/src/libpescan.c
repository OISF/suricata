/*
  libpescan.c

  Libpescan provides identification of anomalous characteristics of portable executables

  Copyright (C) 2012 BAE Systems Information Solutions Inc.

  This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

  References
  1-'Encoded Executable File Detection Technique via Executable File header Analysis', Choi/Kim/Oh/Ryou

 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "libpescan.h"

#define DOS_HDR_SIZE  64
#define GOOD_NAMES    8192

/**
 *   known section names for exe's, dll's
 *   Windows Install
 *   VC++
 *   gcc
 *
 */

char * good_sect_names[GOOD_NAMES]= {
        "ALMOSTRO",
        ".aomadmi",
        "ASM",
        "BASE",
        ".bldvar",
        ".bootdat",
        ".bss",
        "BSS",
        "BSS_NP",
        "cachelin",
        ".cdata",
        ".chs_dat",
        ".cht_dat",
        ".CLR_UEF",
        "CODE",
        "CODE_NP",
        "Common",
        "CONST",
        ".CRT",
        "cseg",
        "CSEG",
        "CURSORS",
        ".data",
        "DATA",
        ".data1",
        "_DATA1",
        "DATA_NP",
        ".dbgmap",
        "dllseg",
        "dseg",
        "DSEG",
        "DUMPDATA",
        ".dxgknpd",
        ".edata",
        "EDTQ",
        "ENGINE",
        ".extjmp",
        ".extrel",
        "FE_TEXT",
        "FINDSHAR",
        ".fusrdat",
        "gdata",
        "GLOBAL_I",
        ".guids",
        "H26xColo",
        "IACODE1",
        "IACODE2",
        "IADATA1",
        "IARDATA2",
        ".idata",
        ".idmbpar",
        ".il",
        ".IMEVPAD",
        "INIT",
        "INITCONS",
        "INITDAT",
        "INITDATA",
        "INITKDBG",
        ".instanc",
        "INSTDATA",
        "ITBL",
        ".its",
        ".kbdfall",
        "_LDATA",
        "_LTEXT",
        ".mc",
        "MISYSPTE",
        "MMXCCDAT",
        "MMXCODE1",
        "MMXDATA1",
        "MMXMEDAT",
        ".MODINIT",
        "MovieMak",
        ".MSIMESH",
        ".mspdta",
        ".ndr64",
        ".nep",
        ".no_bbt",
        "NONPAGE",
        "NONPAGED",
        ".orpc",
        "page",
        "Page",
        "PAGE",
        "PAGE4BRO",
        "PAGE5NET",
        "PAGE8FIL",
        "PAGEABLE",
        "PAGEAFD",
        "PAGE_BIO",
        "PAGEBSS",
        "PAGECDNC",
        "PAGECDOT",
        "PAGE_COM",
        "PAGECONS",
        "PAGED",
        "PAGE_DAT",
        "PAGEDATA",
        "PAGED_CO",
        "PAGEDDAT",
        "PAGE_DDC",
        "PAGEHDLS",
        "PAGEHIT2",
        "PAGEHITA",
        "PAGE_INI",
        "PAGEIPMc",
        "PAGEIPX",
        "PAGEIRDA",
        "PAGEKD",
        "PAGEKRPC",
        "PAGELK",
        "PAGELK16",
        "PAGELKCO",
        "PAGELOCK",
        "PAGEMOUC",
        "PAGEMSBN",
        "PAGEMSG",
        "PAGENBT",
        "PAGENDCO",
        "PAGENDSE",
        "PAGENDSM",
        "PAGENDSP",
        "PAGENDST",
        "PAGE_NO_",
        "PAGENPNP",
        "PAGEPARW",
        "PAGEPTCH",
        "PAGER32C",
        "PAGER32R",
        "PAGERPCD",
        "PAGERT",
        "PAGERW",
        "PAGESAN",
        "PAGESCAN",
        "PAGESENM",
        "PAGESER",
        "PAGESMBC",
        "PAGESMBD",
        "PAGESPEC",
        "PAGESRP0",
        "PAGESSL",
        "PAGETOSH",
        "PAGEUBS0",
        "PAGEUMDM",
        "PAGEUPDT",
        "PAGEUSBS",
        "PAGEVRF1",
        "PAGEVRF2",
        "PAGEVRFB",
        "PAGEVRFC",
        "PAGEVRFD",
        "PAGEVRFY",
        "PAGEWMI",
        ".pdata",
        ".pexe",
        "POOLCODE",
        "POOLMI",
        ".Provide",
        ".rdata",
        ".reloc",
        ".rodata",
        ".rsrc",
        "RT",
        "RT_BSS",
        "RT_CODE",
        "RT_CONST",
        "RT_DATA",
        "RTFOUT_P",
        "RWEXEC",
        "SANONTCP",
        ".scansrv",
        ".sdata",
        ".sdbid",
        "SECUR",
        ".sgroup",
        ".shared",
        "Shared",
        "SHARED",
        ".ShareDa",
        ".shdat",
        ".SMEM",
        "SPINLOCK",
        ".STL",
        ".sxdata",
        "_TEST",
        ".text",
        ".text2",
        "__TEXT",
        "TEXT",
        ".text_hf",
        ".tls",
        ".TLS",
        "TSHEAP",
        "UPX0",
        "UPX1",
        "UPX2",
        "WPCHMAP",
        "WPCODES",
        ".xdata",
        0
};

/*
 * This function checks for sections names
 * not included in the whitelist above.
 *
 */

int
bad_sect_name( char *s ) {
    int k;
    for(k=0;good_sect_names[k];k++) {
        if( strcasecmp(s,good_sect_names[k])==0 )
            return 0;
    }
    return 1;
}

// feature vector code
void fvinit( peattrib_t * wp ) {
    int i;
    for(i=0;i<FV_MAX;i++)
        wp->fv[i]=0;
    wp->fvflags=0;
    wp->fvflagcnt=0;
}

void fvset( peattrib_t * wp, int index, int value ) {
    if( !(wp->fvflags & (1<<index)) )
        wp->fvflagcnt++;
    wp->fvflags |= 1<<index;
    wp->fv[index] = value;
}

void fvadd( peattrib_t * wp, int index, int value ) {
    if( !(wp->fvflags & (1<<index)) )
        wp->fvflagcnt++;
    wp->fvflags |= 1<<index;
    wp->fv[index] += value;
}

// Setting up pescore to provide the Root-Means-Squared score calculation.
double pescore( peattrib_t * wp ) {
    int i;
    double x=0.0;

    for(i=0;i<FV_MAX;i++)
        x += wp->fv[i] * wp->fv[i];

    if( x > 0.0 )
        x = sqrt( x );

    return x;
}

static
unsigned getword(unsigned  char * p ) {
    unsigned w;
    w = p[0] | (p[1]<<8) ;
    return w;
}

static
unsigned getdword(unsigned  char * p ) {
    unsigned w;
    w = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24) ;
    return w;
}

/*
  Headers
  ----------------------------------------------------
  DOS Hdr : variable : >=128,  PE-offset@60,61, DOS text@78 ...
  Unused area : vasriable
  PE Sig, aligned on 8 byte boundary
  Image File Header  : 20 bytes
  Optional Header    : PE32=>96+nrva*8, PE32+=>112+nrva*8
  Section Table      : 40 bytes per section header

  Header  Sizes
  ----------------------------------------------------
  DOS   Size = 128+
  PE32  Size = 4+20+96 +40*nsections+nrva*8 = 120+40*nsections+nrva*8
  PE32+ Size = 4+20+112+40*nsections+nrva*8 = 136+40*nsections+nrva*8

  returns:
  0 no mz found, cannot be a pe
  < 0 various error issues: truncation of header, or bogus header data
  > 0 peoffset, header prcoessed
  offset : mz offset

  buf	: buffer to scan
  nbuf	: bytes in buf
  offset	: offset of mz
  petype	: 32/64 bit flags, and
  v	: verbose flag
 */

/* The pescan function checks the PE file to ensure it
 * is not truncated, and if so, reports an error and
 *  stops scanning the affected file...MER 04/30/12
 *
 */

int
pescan( peattrib_t * wp, unsigned char * buf, int nbuf, int debug ) {
    unsigned char * p;
    unsigned char * mz=0;
    unsigned nleft;
    //int mzoffset=0;
    //unsigned peoffset=0;
    int i;
    int pever=0;
    unsigned nrva;
    unsigned char * pq;
    unsigned nsections;
    unsigned k;
    int nexecs=0;
    unsigned scs=0;
    unsigned sud=0;
    unsigned sid=0;
    unsigned tcs=0;
    unsigned tud=0;
    unsigned tid=0;

    unsigned entryptr;   //Relative to image base
    unsigned baseofcode;
    unsigned w;
    unsigned ifh;             // image file header info
    unsigned oh;              // optional header offset
    unsigned ohbasesize;      // size of base optional header, excludes rva's
    unsigned magic;

    memset(wp,0,sizeof(peattrib_t));

    nleft = nbuf;
    p = buf;

    if( nbuf < 2 )
        return PE_NOT_PE;

    // Scan for an MZ
    for(i=0;i<nbuf-1;i++) {
        if( p[i]=='M' && p[i+1]=='Z' ) {
            mz = &p[i];
            break;
        }
    }
    if( !mz )
        return PE_NOT_PE;

    if( debug ) printf("MZ DOS signature found!\n");

    wp->mzoffset = mz - p;

    nleft = nbuf - wp->mzoffset;

    if( nleft < 62 ) { // MZ found, not enough buffer
        wp->trunc=1;
        return PE_INDETERMINATE;
    }

    wp->peoffset = mz[60] + (mz[61]<<8); // offset of PE,NE,etc..

    fvinit( wp );

    // Test that the offset is within the buffer
    if( wp->peoffset+1 > nleft ) {
        wp->trunc=1;
        return PE_INDETERMINATE;
    }

    // Verify PE
    if( (mz[wp->peoffset]!='P')||(mz[wp->peoffset+1]!='E')||(mz[wp->peoffset+2]!=0)||(mz[wp->peoffset+3]!=0))
        return PE_NOT_PE;

    if( debug ) printf("libpescan: MZ+PE signature found!\n");

    // ImageFileHeader
    ifh = wp->peoffset+4;

    // Check for a Full Image File Header
    if( ifh + 20 > nleft ) {
        wp->trunc=1;
        return  PE_TRUNCATED;  // incomplete image header
    }

    // Machine WORD
    wp->machine = w = getword(mz+ifh);
    if( debug ) printf("libpescan: machine = %x\n",wp->machine);
    if( w != 0x014c /* 32bit*/ &&  w != 0x8664 /* x86_64 bit*/ )
        return PE_IFH_NOT3264;

    wp->nsections = nsections = w = getword(mz+ifh+2);
    if( debug ) printf("libpescan: nsectors = %d\n",wp->nsections);
    if( nsections > 100 ) {
        //printf("warning: nsections seems excessive : %u \n",nsections);
        return PE_BAD_DATA;
    }

    wp->tstamp =getdword(mz+ifh+4);

    wp->opt_hdr_size =getword(mz+ifh+16);
    if( debug ) printf("libpescan: opt hdr size = 0x%x\n",wp->opt_hdr_size);
    if( wp->opt_hdr_size == 0 )
        return PE_NOT_PE;

    // Characteristics WORD
    w = getword(mz+ifh+18);
    if( debug ) printf("libpescan: characteristics = 0x%x\n", w );
    if( w & 0x02 ) // EXE
        wp->petype |= PE_EXE;
    if( w & 0x2000 ) // DLL
        wp->petype |= PE_DLL;
    if( w & 0x1000 ) // SYSTEM FILE
        wp->petype |= PE_SYS;

    if( !(w&0x2) ) { // EXE
        return PE_IFH_NOT_BINARY;
    }

    // Standard Optional Header Info space
    oh = ifh + 20;
    if( oh + 2 > nleft ) { // test for minimal set of fields
        wp->trunc=1;
        return  PE_TRUNCATED;  // incomplete image header
    }

    // Magic - selects PE32/PE32+
    magic = getword(mz+oh);
    if( debug ) printf("libpescan: magic = 0x%x\n", magic );
    if( magic == 0x10b ) {
        pever=32;
        wp->pesize = PE_32;
        ohbasesize = 96;
    }
    else if( magic == 0x20b ) {
        pever=64;
        wp->pesize = PE_64;
        ohbasesize = 112;
    }
    else {
        return PE_OH_BAD_MAGIC; // bad magic
    }

    //if( oh + ohbasesize > nleft )
    // needs to be this big to find SubSystem value, required by all version of windows
    // this helps read tiny PE's, that may overlap sections ...
    if( oh + 72 > nleft ) {
        wp->trunc=1;
        return  PE_TRUNCATED;
    }
    // optional header standard fields
    wp->link_major = w = mz[oh+2];
    wp->link_minor = w = mz[oh+3];
    tcs = wp->size_of_code = getdword(mz+oh+4);
    tid = wp->size_of_data = getdword(mz+oh+8);
    tud = wp->size_of_udata = getdword(mz+oh+12);
    wp->entryptr = entryptr = getdword(mz+oh+16);
    wp->base_of_code = baseofcode = getdword(mz+oh+20);

    if( magic == 0x10B ) //PE32
        wp->image_base = getdword(mz+oh+28);
    else if( magic == 0x20B ) //PE32+
        wp->image_base = getdword(mz+oh+24);

    wp->sect_align = getdword(mz+oh+32);
    wp->file_align = getdword(mz+oh+36);


    // optional header windows specific fields
    wp->os_major = getword(mz+oh+40);
    wp->os_minor = getword(mz+oh+42);
    wp->size_of_image = getdword(mz+oh+56);
    wp->size_of_hdrs  = getdword(mz+oh+60);
    wp->chksum = getdword(mz+oh+64);
    wp->subsystem = getdword(mz+oh+68);

    if( oh + ohbasesize + 16 > nleft ) { //nuff buffer for exp/imp tables ??

        wp->trunc=1;
        return  PE_TRUNCATED;  // cannot read export,import table info, not in buffer
    }

    nrva = 16;
    if( pever == 32 ) {
        if( oh + 96  < nleft )
            wp->nrva = nrva = getdword(mz+oh+92);  //# data dirs
    }
    else if( pever == 64 ) {
        if( oh + 112  < nleft )
            wp->nrva = nrva = getdword(mz+oh+108);  //# data dirs
    }
    if(debug) printf("libpescan: number of data dirs = 0x%x\n",nrva);
    nrva = 16;

    if( oh + ohbasesize + 16  > nleft ) {
        wp->trunc=1;
        return  PE_TRUNCATED;  // cannot read export,import table info, not in buffer
    }

    // Data Directory Info
    if( pever==32 ) {
        wp->export_rva  = w = getdword(mz+oh+96);  //export
        wp->export_size = w = getdword(mz+oh+100);
        wp->import_rva  = w = getdword(mz+oh+104);  //import
        wp->import_size = w = getdword(mz+oh+108);
        wp->rsrc_rva  = w = getdword(mz+oh+112);  //rscr
        wp->rsrc_size = w = getdword(mz+oh+116);
    }
    else if( pever==64 ) {
        wp->export_rva  = w = getdword(mz+oh+112);  //export
        wp->export_size = w = getdword(mz+oh+120);
        wp->import_rva  = w = getdword(mz+oh+128);  //import
        wp->import_size = w = getdword(mz+oh+136);
        wp->rsrc_rva  = w = getdword(mz+oh+128);  //rscr
        wp->rsrc_size = w = getdword(mz+oh+132);
    }


    // Section Headers - sections flow opt_hdr_size ...
    for(k=0;k<nsections;k++) {
        int pcnt,npcnt,kk;
        unsigned rva;
        unsigned rvsize;
        unsigned rawsize;

        /// out of bounds check, includes length of this section ....
        if( oh + wp->opt_hdr_size + (k+1)*40 > nleft ) {
            wp->trunc=1;
            return  PE_TRUNCATED;
        }

        pq = mz + oh + wp->opt_hdr_size + k*40;

        pcnt=npcnt=0;

        memcpy(wp->sx[k].name,pq,8);

        // count leading non-printabls chars, and printable chars...
        for(kk=0;kk<8 ;kk++) {
            if( pq[kk] > 32 && pq[kk]<=127 ) pcnt++;
            if( (pcnt==0) && (pq[kk] <=32 || pq[kk]>127) ) npcnt++;
        }

        if( npcnt > 0 ) fvadd( wp, NON_PRINT_NAME, 2 ); // non printables

        wp->sx[k].virt_size  = rvsize = getdword(pq+8);
        wp->sx[k].virt_rva   = rva = getdword(pq+12);
        wp->sx[k].raw_size   = rawsize = getdword(pq+16);
        wp->sx[k].raw_offset = getdword(pq+20);


        w = wp->sx[k].cx =  getdword(pq+36);
        if( w & 0x20 ) scs+=rawsize;
        if( w & 0x40 ) sid+=rawsize;
        if( w & 0x80 ) sud+=rawsize;
        if( w & 0x20000000 ) nexecs++;

        if( (w & (0x20000000|0x80000000)) == (0x20000000|0x80000000) ) // exec + write
            fvadd( wp, EXEC_AND_WRITE, (w & (0x20000000|0x80000000) ) ? 1 : 0 );

        if( (w & (0x20000000|0x20)) == 0x20000000 ) // exec, no code
            fvadd( wp, EXEC_NOT_CODE, 1 );

        if( (w & (0x20000000|0x20)) == 0x20 )// code, no exec
            fvadd( wp, EXEC_NOT_CODE, 1 );

        if( (entryptr >= rva) && (entryptr <= rva+rvsize) ) {
            if( !(w & 0x20000000) ) //no exec
                fvset( wp, ENTRY_NO_EXEC, 1 );
            if( !(w & 0x20) ) // no code
                fvset( wp, ENTRY_NO_CODE, 1 );
        }
    }

    if( scs > tcs ) // sum of sector code size larger than sizeofcode in optional header
        fvadd( wp, BAD_CODE_SUM, 1);

    if( sid > tid ) // init data
        fvadd( wp, BAD_DATA_SUM, 1);

    if( sud > tud ) // uninit data
        fvadd( wp, BAD_UDATA_SUM, 1);

    if( scs > tcs ) // sum of sector code size larger than sizeofcode in optional header
        wp->isize|=1;
    if( sid > tid ) // init data
        wp->isize|=2;
    if( sud > tud ) // uninit data
        wp->isize|=4;


    return wp->peoffset + (mz-p); // relative to beginning of buffer
}

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/libpescan.h"

#define	BUF_SIZE	4096

void printfv( FILE * fp, peattrib_t * wp, int flag, char * s )
{
    if( wp->fv[flag] )
        fprintf(fp,"%s=%1d\n", s, wp->fv[flag] );
}

void fvscore( FILE * fp, peattrib_t * wp, double (*fptr)(peattrib_t * pestruct) )
{
    wp->pescore = 0.0;
    wp->pescore = (*fptr)(wp);

    fprintf(fp,"pe_score=%g \n",wp->pescore);
    fprintf(fp,"pe_flags=0x%x \n",wp->fvflags);
    fprintf(fp,"pe_flagcount=%d \n",wp->fvflagcnt);

    if( wp->pescore > 0.0 )
    {
        printfv(fp, wp, EXEC_AND_WRITE, "pe_flag_exec_and_write");
        printfv(fp, wp, EXEC_NOT_CODE,  "pe_flag_exec_no_code");
        printfv(fp, wp, NON_PRINT_NAME, "pe_flag_non_printable");
        printfv(fp, wp, NO_EXEC_BIT,    "pe_flag_no_exec_bit");
        printfv(fp, wp, BAD_CODE_SUM,   "pe_flag_code_sum_err");
        printfv(fp, wp, BAD_DATA_SUM,   "pe_flag_data_sum_err");
        printfv(fp, wp, BAD_UDATA_SUM,  "pe_flag_udata_sum_err");
        printfv(fp, wp, ENTRY_NO_EXEC,  "pe_flag_entry_no_exec");
        printfv(fp, wp, ENTRY_NO_CODE,  "pe_flag_entry_no_code");
    }
}

int pescore_buf( peattrib_t * wp, char * buf, int n, double (*fptr)(peattrib_t * pestruct) )
{

    int m=0;
    buf[0]=0;
    wp->pescore = 0.0;
    wp->pescore = (*fptr)(wp);

    if( n < 20 ) return wp->pescore;

    m+=snprintf(buf+m,n-m, "pe_score=%g \n", wp->pescore); /* always provide a score ... */
    if( m > n-40 ) return wp->pescore;

    m+=snprintf(buf+m,n-m, "pe_flags=0x%x \n", wp->fvflags); /* always provide flags */
    if( m > n-40 ) return wp->pescore;

    m+=snprintf(buf+m,n-m, "pe_flagcnt=%d \n", wp->fvflagcnt); /* always provide flags */
    if( m > n-40 ) return wp->pescore;

    if(wp->fv[0]) m+=snprintf(buf+m,n-m, "pe_flag_exec_and_write=%1d \n",wp->fv[0]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[1]) m+=snprintf(buf+m,n-m, "pe_flag_exec_no_code=%1d \n",  wp->fv[1]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[2]) m+=snprintf(buf+m,n-m, "pe_flag_non_printable=%1d ", wp->fv[2]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[3]) m+=snprintf(buf+m,n-m, "pe_flag_no_exec=%1d \n",       wp->fv[3]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[4]) m+=snprintf(buf+m,n-m, "pe_flag_code_sum=%1d \n",      wp->fv[4]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[5]) m+=snprintf(buf+m,n-m, "pe_flag_data_sum=%1d \n",      wp->fv[5]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[6]) m+=snprintf(buf+m,n-m, "pe_flag_udata_sum=%1d \n",     wp->fv[6]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[7]) m+=snprintf(buf+m,n-m, "pe_flag_entry_not_exec=%1d \n",wp->fv[7]);  if( m > n-40 ) return wp->pescore;
    if(wp->fv[8]) m+=snprintf(buf+m,n-m, "pe_flag_entry_not_code=%1d \n",wp->fv[8]);  if( m > n-40 ) return wp->pescore;

    return m;
}

int main(int argc, char **argv)
{
    int opt = 0;
    int index = 0;
    int debug = 0;
    int stat;
    int nread;
    int res;
    char * flags = "af";
    char * pefile;
    FILE * fd;
    unsigned char pebuf[BUF_SIZE];
    unsigned char * peptr = pebuf;
    char outbuf[BUF_SIZE];
    char * outptr = outbuf;
    peattrib_t wp;

    opt = getopt( argc, argv, flags );
    printf("opt=%d\n", opt);
    for( index = optind; index < argc; index++ )
    {
        pefile = argv[index];
        if( (fd = fopen(pefile, "rb")) == NULL )
        {
            perror("fopen error");
            continue;
        }

        if( (nread = fread( peptr, BUF_SIZE, 1, fd)) < 0 )
        {
            perror("fread error");
            continue;
        }

        stat = pescan(&wp, peptr, BUF_SIZE, debug);
        if( stat == PE_BAD_DATA )
        {
            fprintf( stderr,"file=%s pe field(s) have read data, stat=%d\n", pefile, stat );
            fclose( fd );
            return -1;
        }
        else if( stat <= 0  )
        {
            fprintf( stderr,"file=%s is not a pe or is truncated, stat=%d\n", pefile, stat );
            fclose( fd );
            return -1;
        }

        res = pescore_buf( &wp, outptr, BUF_SIZE, pescore );
        printf("res=%d\n", res);
        fprintf( stdout, "%s", outptr );
        fclose( fd );
    }

    return 0;
}

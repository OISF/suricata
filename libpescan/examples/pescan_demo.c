#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../libpescan.h"

#define	BUF_SIZE	4096

// This function determines the characteristics of each section of a PE.
static
void
cxprint(char * buf, int blen,unsigned w)
{
    int n=0;

    buf[0]=0;

    if( w & 0x20 )
	n+=snprintf(buf+n,blen-n,"code ");
    if( blen-n < 20 ) return;

    if( w & 0x40 )
	n+=snprintf(buf+n,blen-n,"data ");
    if( blen-n < 20 ) return;

    if( w & 0x80 )
	n+=snprintf(buf+n,blen-n,"udata ");
    if( blen-n < 20 ) return;

    if( w & 0x00010000 )
	n+=snprintf(buf+n,blen-n,"reserved ");
    if( blen-n < 20 ) return;

    if( w & 0x00020000 )
	n+=snprintf(buf+n,blen-n,"reserved ");
    if( blen-n < 20 ) return;

    if( w & 0x00040000 )
	n+=snprintf(buf+n,blen-n,"reserved ");
    if( blen-n < 20 ) return;

    if( w & 0x00080000 )
	n+=snprintf(buf+n,blen-n,"reserved ");
    if( blen-n < 20 ) return;

    if( w & 0x00f00000 )
	n+=snprintf(buf+n,blen-n,"alignment ");
    if( blen-n < 20 ) return;

    if( w & 0x02000000 )
	n+=snprintf(buf+n,blen-n,"discard ");
    if( blen-n < 20 ) return;

    if( w & 0x04000000 )
	n+=snprintf(buf+n,blen-n,"nocache ");
    if( blen-n < 20 ) return;

    if( w & 0x08000000 )
	n+=snprintf(buf+n,blen-n,"nopage ");
    if( blen-n < 20 ) return;

    if( w & 0x10000000 )
	n+=snprintf(buf+n,blen-n,"shared ");
    if( blen-n < 20 ) return;

    if( w & 0x20000000 )
	n+=snprintf(buf+n,blen-n,"execute ");
    if( blen-n < 20 ) return;

    if( w & 0x40000000 )
	n+=snprintf(buf+n,blen-n,"read ");
    if( blen-n < 20 ) return;

    if( w & 0x80000000 )
	n+=snprintf(buf+n,blen-n,"write ");
    if( blen-n < 20 ) return;

    if( n > 0 ) buf[n-1] = 0;
}

void
print_peattrib( FILE *fp, peattrib_t * wp, int longformat )
{
    int w;
    int i;
    time_t ts;

    w = wp->machine;

    ts = wp->date;
    fprintf(fp,"pe_date = %x : %s",(unsigned)wp->date, ctime(&ts) );

    fprintf(fp,"pe_offset=%d\n",wp->peoffset);

    fprintf(fp,"pe_mach_bits=");
    if( w == 0x014c ) // 32bit
	{
	    fprintf(fp,"32 ");
	}
    else if( w == 0x8664 ) // x86_64 bit
	{
	    fprintf(fp,"64 ");
	}
    else
	{
	    fprintf(fp,"0x%x ", w );
	}
    if( longformat)fprintf(fp,"\n");

    fprintf(fp,"pe_os_version=%d.%d ",wp->os_major,wp->os_minor);
    if( longformat)fprintf(fp,"\n");

    w = wp->petype;
    fprintf(fp,"pe_binary=");
    if( w & PE_EXE ) fprintf(fp,"EXE");
    else            fprintf(fp,"NONEXE");
    if( w & PE_DLL ) fprintf(fp,"/DLL");
    if( w & PE_SYS ) fprintf(fp,"/SYS");
    fprintf(fp," ");
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_num_sections=%u ",wp->nsections);
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_image_size=0x%x ", wp->size_of_image);
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_opt_hdr_size=%u ", wp->opt_hdr_size);
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_hdr_fmt=%s ", (wp->pesize==PE_32)?"PE32":((wp->pesize==PE_64)?"PE64":"??") );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_link_ver=%d.%d ", wp->link_major,wp->link_minor);
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_code_size=0x%x ", wp->size_of_code  );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_data_size=0x%x ", wp->size_of_data  );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_udata_size=0x%x ", wp->size_of_udata );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_entry_point=0x%x ", wp->entryptr );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_baseof_code=0x%x ", wp->base_of_code );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_sizeof_hdrs=0x%x ", wp->size_of_hdrs );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_num_rva_dirs=0x%x ", wp->nrva );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_export_va=0x%x ", wp->export_rva );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_export_size=0x%x ", wp->export_size );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_import_va=0x%x ", wp->import_rva );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_rsrc_size=0x%x ", wp->rsrc_size );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_tls_va=0x%x ", wp->tls_rva );
    if( longformat)fprintf(fp,"\n");
    fprintf(fp,"pe_tls_size=0x%x ", wp->tls_size );
    if( longformat)fprintf(fp,"\n");

    if( wp->isize & 1 ){
	fprintf(fp,"pe_code_size=1 ");  //commented out originally...MER 051812
	if( longformat)fprintf(fp,"\n");
    }
    if( wp->isize & 2 ){
	fprintf(fp,"pe_flag_data_sum=1 "); //commented out originally...mER 051812
	if( longformat)fprintf(fp,"\n");
    }
    if( wp->isize & 4 ){
	fprintf(fp,"pe_udata_size=1 ");
	if( longformat)fprintf(fp,"\n");
    }

    for(i=0;i<wp->nsections;i++)
	{
	    int k;
	    fprintf(fp,"pe_sect_name='");
	    for(k=0;k<8;k++)
		{
		    if( wp->sx[i].name[k] >32 && wp->sx[i].name[k] <=127 )
			fprintf(fp,"%c",wp->sx[i].name[k]);
		}
	    fprintf(fp,"' ");

	    if( longformat)fprintf(fp,"\n");
	    w=wp->sx[i].cx;
	}
    fprintf(fp,"\n");

    for(i=0;i<wp->nsections;i++)
	{
	    int k;
	    fprintf(fp,"pe_section= '");
	    for(k=0;k<8;k++)
		{
		    if( wp->sx[i].name[k] >32 && wp->sx[i].name[k] <=127 )
			fprintf(fp,"%c",wp->sx[i].name[k]);
		}
	    fprintf(fp,"'");
	    fprintf(fp," virt-size= 0x%x",wp->sx[i].virt_size);
	    fprintf(fp," virt-addr= 0x%x",wp->sx[i].virt_rva);
	    fprintf(fp," raw-size= 0x%x",wp->sx[i].raw_size);
	    fprintf(fp," raw-off= 0x%x",wp->sx[i].raw_offset);
	    fprintf(fp," cflags= %x : ", w=wp->sx[i].cx );
	    if( w & 0x20 ) fprintf(fp,"code ");
	    if( w & 0x40 ) fprintf(fp,"data ");
	    if( w & 0x80 ) fprintf(fp,"udata ");
	    if( w & 0x00010000 ) fprintf(fp,"reserved ");
	    if( w & 0x00020000 ) fprintf(fp,"reserved ");
	    if( w & 0x00040000 ) fprintf(fp,"reserved ");
	    if( w & 0x00080000 ) fprintf(fp,"reserved ");
	    if( w & 0x00f00000 ) fprintf(fp,"alignment ");
	    if( w & 0x02000000 ) fprintf(fp,"discard ");
	    if( w & 0x04000000 ) fprintf(fp,"nocache ");
	    if( w & 0x08000000 ) fprintf(fp,"nopage ");
	    if( w & 0x10000000 ) fprintf(fp,"shared ");
	    if( w & 0x20000000 ) fprintf(fp,"execute ");
	    if( w & 0x40000000 ) fprintf(fp,"read ");
	    if( w & 0x80000000 ) fprintf(fp,"write ");
	    fprintf(fp,"\n");
	}
}

int
pe_print_buf( peattrib_t * wp, char * sbuf, int slen )
{
    int w;
    int i;
    char buf[256];
    int m=0;

    w = wp->machine;

    if( wp->trunc )
	m+=snprintf(sbuf+m,slen-m,"pe_truncated ");
    if( slen-m < 20 ) return m;

    if( w == 0x014c ) // 32bit
	{
	    m+=snprintf(sbuf+m,slen-m,"pe_mach_bits=32 ");
	}
    else if( w == 0x8664 ) // x86_64 bit
	{
	    m+=snprintf(sbuf+m,slen-m,"pe_mach_bits=64 ");
	}
    else
	{
	    m+=snprintf(sbuf+m,slen-m,"pe_mach_bits=0x%x ",w);
	}
    if( slen-m < 20 ) return m;

    m+=snprintf(sbuf+m,slen-m,"pe_hdr_type=%s ", (wp->pesize==PE_32)?"PE32":((wp->pesize==PE_64)?"PE64":"??") );
    if( slen-m < 20 ) return m;

    m+=snprintf(sbuf+m,slen-m,"pe_os_version=%d.%d ",wp->os_major,wp->os_minor);
    if( slen-m < 20 ) return m;

    m+=snprintf(sbuf+m,slen-m,"pe_offset=%d ",wp->peoffset);
    if( slen-m < 20 ) return m;

    w = wp->petype;
    m+=snprintf(sbuf+m,slen-m,"pe_binary=");
    if( slen-m < 20 ) return m;
    if( w & PE_EXE ) m+=snprintf(sbuf+m,slen-m,"EXE");
    else            m+=snprintf(sbuf+m,slen-m,"NONEXE");
    if( slen-m < 20 ) return m;
    if( w & PE_DLL ) m+=snprintf(sbuf+m,slen-m,"/DLL");
    if( slen-m < 20 ) return m;
    if( w & PE_SYS ) m+=snprintf(sbuf+m,slen-m,"/SYS");
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m," ");
    if( slen-m < 20 ) return m;

    m+=snprintf(sbuf+m,slen-m,"pe_checksum=0x%x ",wp->chksum);
    if( slen-m < 20 ) return m;

    m+=snprintf(sbuf+m,slen-m,"pe_num_sections=%u ",wp->nsections);
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_image_size=%x ", wp->size_of_image);
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_opt_hdr_size=%u ", wp->opt_hdr_size);
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_link_ver=%d.%d ", wp->link_major,wp->link_minor);
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_code_size=0x%x ", wp->size_of_code  );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_data_size=0x%x ", wp->size_of_data  );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_udata_size=0x%x ", wp->size_of_udata );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_entry_point=0x%x ", wp->entryptr );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_baseof_code=0x%x ", wp->base_of_code );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_sizeof_hdrs=0x%x ", wp->size_of_hdrs );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_num_rva_dirs=0x%x ", wp->nrva );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_export_va=0x%x ", wp->export_rva );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_export_size=0x%x ", wp->export_size );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_import_va=0x%x ", wp->import_rva );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_import_size=0x%x ", wp->import_size );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_rsrc_rva=0x%x ", wp->rsrc_rva );
    if( slen-m < 20 ) return m;
    m+=snprintf(sbuf+m,slen-m,"pe_rsrc_size=0x%x ", wp->rsrc_size );
    if( slen-m < 20 ) return m;

    for(i=0;i<wp->nsections;i++)
	{
	    int k;
	    m+=snprintf(sbuf+m,slen-m,"pe_section_name='");
	    if( slen-m < 20 ) return m;
	    for(k=0;k<8;k++)
		{
		    if( wp->sx[i].name[k] >32 && wp->sx[i].name[k] <=127 )
			m+=snprintf(sbuf+m,slen-m,"%c",wp->sx[i].name[k]);
		}
	    m+=snprintf(sbuf+m,slen-m,"' ");
	    if( slen-m < 20 ) return m;

	    m+=snprintf(sbuf+m,slen-m, "pe_section_raw_size=0x%x ",wp->sx[i].raw_size);
	    if( slen-m < 20 ) return m;
	    m+=snprintf(sbuf+m,slen-m, "pe_section_raw_offset=0x%x ",wp->sx[i].raw_offset);
	    if( slen-m < 20 ) return m;

	    m+=snprintf(sbuf+m,slen-m, "pe_section_virt_size=0x%x ",wp->sx[i].virt_size);
	    if( slen-m < 20 ) return m;
	    m+=snprintf(sbuf+m,slen-m, "pe_section_virt_addr=0x%x ",wp->sx[i].virt_rva);
	    if( slen-m < 20 ) return m;

	    w=wp->sx[i].cx;
	    m+=snprintf(sbuf+m,slen-m,"pe_section_flags='" );
	    if( slen-m < 20 ) return m;

	    cxprint(buf,sizeof(buf),w);

	    m+=snprintf(sbuf+m,slen-m,"%s' ",buf);
	    if( slen-m < 20 ) return m;
	}

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
    char pebuf[BUF_SIZE];
    char * peptr = pebuf;
    char outbuf[BUF_SIZE];
    char * outptr = outbuf;
    peattrib_t wp;

    opt = getopt( argc, argv, flags );
    for( index = optind; index < argc; index++ )
	{
	    pefile = argv[index];
	    if( (fd = fopen(pefile, "rb")) <= 0 )
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

	    pe_print_buf( &wp, outptr, BUF_SIZE );
	    fprintf( stdout, "%s", outptr );
	    fclose( fd );
	}

    return 0;
}

/* Test-only syscall boundary. The production executable has no fixture path.
 * Compile this translation unit ONLY for the offline fault-injection suite. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int fixture_open(const char *,int,...);
static FILE *fixture_fopen(const char *,const char *);
static int fixture_access(const char *,int);
static int fixture_stat(int,struct stat *);
static int fixture_ioctl(int,unsigned long,void *);
static int fixture_close(int);
static ssize_t fixture_pread(int,void *,size_t,off_t);
static ssize_t fixture_pwrite(int,const void *,size_t,off_t);
static uid_t fixture_uid(void) { return 0; }
#define open fixture_open
#define fopen fixture_fopen
#define access fixture_access
#define fstat fixture_stat
#define ioctl fixture_ioctl
#define close fixture_close
#define pread fixture_pread
#define pwrite fixture_pwrite
#define geteuid fixture_uid
#define main bb_production_main
#include "am3_bb_nand_window.c"
#undef main
#undef open
#undef fopen
#undef access
#undef fstat
#undef ioctl
#undef close
#undef pread
#undef pwrite
#undef geteuid

static const char *fixture_root;
static int descriptor_part[4096];
static int erased, pages_written;
static char translated[4096];
static int fault(const char *name) { return getenv("BB_FAULT") && !strcmp(getenv("BB_FAULT"),name); }
static const char *map_path(const char *path) {
    if(!strncmp(path,"/dev/",5) || !strncmp(path,"/proc/",6) ||
       !strncmp(path,"/sys/",5) || !strncmp(path,"/etc/",5)) {
        if(snprintf(translated,sizeof(translated),"%s%s",fixture_root,path)>=(int)sizeof(translated)) abort();
        return translated;
    }
    return path;
}
static void event(const char *name,int part,off_t offset) {
    char path[4096]; snprintf(path,sizeof(path),"%s/events",fixture_root);
    FILE *file=fopen(path,"a");
    if(!file) abort();
    fprintf(file,"%s mtd%d %ld\n",name,part,(long)offset);
    fclose(file);
}
static int fixture_open(const char *path,int flags,...) {
    mode_t mode=0;
    if(flags&O_CREAT) { va_list args; va_start(args,flags); mode=(mode_t)va_arg(args,int); va_end(args); }
    unsigned part; char extra;
    int is_part=sscanf(path,"/dev/mtd%u%c",&part,&extra)==1 && part<12;
    int fd=open(map_path(path),flags,mode);
    if(fd>=0 && fd<4096) descriptor_part[fd]=is_part ? (int)part+1 : 0;
    return fd;
}
static FILE *fixture_fopen(const char *path,const char *mode) { return fopen(map_path(path),mode); }
static int fixture_access(const char *path,int mode) { return access(map_path(path),mode); }
static int fixture_stat(int fd,struct stat *st) {
    int result=fstat(fd,st);
    if(!result && fd<4096 && descriptor_part[fd]) {
        st->st_mode=(st->st_mode&~S_IFMT)|S_IFCHR;
        st->st_rdev=makedev(90,2*(descriptor_part[fd]-1));
    }
    return result;
}
static int fixture_ioctl(int fd,unsigned long request,void *arg) {
    if(fd>=4096 || !descriptor_part[fd]) { errno=ENOTTY; return -1; }
    unsigned part=(unsigned)descriptor_part[fd]-1;
    if(request==MEMGETINFO) {
        struct mtd_info_user *info=arg;
        memset(info,0,sizeof(*info)); info->type=MTD_NANDFLASH;
        info->size=parts[part].size; info->erasesize=ERASE; info->writesize=PAGE;
        if(fault("geometry")) info->writesize=4096;
        return 0;
    }
    if(request==MEMGETBADBLOCK) return fault("bad-block") && *(int64_t *)arg==0 ? 1 : 0;
    if(request==MEMERASE) {
        struct erase_info_user *erase=arg;
        event("erase",part,erase->start);
        if(fault("erase")) { errno=EIO; return -1; }
        if(erase->start%ERASE || erase->length!=ERASE || erase->start+ERASE>parts[part].size) abort();
        unsigned char bytes[ERASE]; memset(bytes,255,ERASE);
        if(pwrite(fd,bytes,ERASE,erase->start)!=ERASE) abort();
        erased++;
        return 0;
    }
    abort();
}
static ssize_t fixture_pwrite(int fd,const void *buf,size_t size,off_t offset) {
    if(fd<4096 && descriptor_part[fd]) {
        event("write",descriptor_part[fd]-1,offset);
        if(fault("write") && pages_written==1) { errno=EIO; return -1; }
        unsigned char old[PAGE];
        if(size>PAGE || pread(fd,old,size,offset)!=(ssize_t)size) abort();
        for(size_t i=0;i<size;i++) if(old[i]!=255) abort();
        pages_written++;
    }
    return pwrite(fd,buf,size,offset);
}
static ssize_t fixture_pread(int fd,void *buf,size_t size,off_t offset) {
    ssize_t got=pread(fd,buf,size,offset);
    if(got>0 && fd<4096 && descriptor_part[fd] && erased) {
        if(fault("readback") && !offset) ((unsigned char *)buf)[0]^=1;
        if(fault("tail") && offset==ERASE) ((unsigned char *)buf)[0]=0;
    }
    return got;
}
static int fixture_close(int fd) {
    int writer=fd<4096 && descriptor_part[fd] && (fcntl(fd,F_GETFL)&O_ACCMODE)==O_RDWR;
    if(fd<4096) descriptor_part[fd]=0;
    int result=close(fd);
    if(writer && erased && fault("sync")) { errno=EIO; return -1; }
    return result;
}
int main(int argc,char **argv) {
    fixture_root=getenv("BB_FIXTURE_ROOT");
    if(!fixture_root || !*fixture_root) return 65;
    return bb_production_main(argc,argv);
}

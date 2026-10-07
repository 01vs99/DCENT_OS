/* SPDX-License-Identifier: GPL-3.0-only
 * BB fixed physical NAND windows. Capsule, recovery, unit and payload boot
 * admission belongs to the transaction. This primitive never reboots and can
 * write only mtd11 nvdata and the single mtd5 environment, from a RAM root.
 * No bad-block skipping: the physical boot addresses may not move.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define ERASE 131072u
#define PAGE 2048u
struct part { const char *name; uint32_t size, offset; };
static const struct part parts[] = {
    {"spl",ERASE,0}, {"spl_backup1",ERASE,0x20000}, {"spl_backup2",ERASE,0x40000},
    {"spl_backup3",ERASE,0x60000}, {"u-boot",0x1c0000,0x80000}, {"bootenv",ERASE,0x240000},
    {"fdt",ERASE,0x260000}, {"kernel",0x500000,0x280000}, {"root",0x1400000,0x800000},
    {"config",0x200000,0x1c00000}, {"sig",0x200000,0x1e00000}, {"nvdata",0x6000000,0x2000000}
};
static void die(const char *message) {
    fprintf(stderr,"am3-bb-nand-window: %s (errno=%d)\n",message,errno);
    exit(1);
}
static void transfer(int fd, void *data, size_t size, off_t offset, int writing) {
    unsigned char *p=data;
    while(size) {
        ssize_t got=writing ? pwrite(fd,p,size,offset) : pread(fd,p,size,offset);
        if(got<0 && errno==EINTR && !writing) continue;
        if(got<=0) die(writing ? "write failed" : "read failed");
        p+=got; offset+=got; size-=(size_t)got;
    }
}
static void text_file(const char *path,char *out,size_t size) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    ssize_t got=fd<0 ? -1 : read(fd,out,size-1);
    if(got<=0 || got==(ssize_t)size-1) die("identity text unavailable/oversize");
    out[got]='\0'; if(out[got-1]=='\n') out[got-1]='\0';
    if(close(fd)) die("identity close");
}
static struct stat directory_identity(const char *path) {
    /* These are kernel-owned sysfs links. Following them is intentional. */
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_DIRECTORY);
    struct stat st;
    if(fd<0 || fstat(fd,&st) || !S_ISDIR(st.st_mode) || close(fd)) die("NAND parent unavailable");
    return st;
}
static void same_directory(struct stat first,struct stat second) {
    if(first.st_dev!=second.st_dev || first.st_ino!=second.st_ino) die("NAND parent/controller differs");
}
static void property(const char *path,const unsigned char *expected,size_t size) {
    unsigned char value[64];
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    ssize_t got=fd<0 ? -1 : read(fd,value,sizeof(value));
    if(got!=(ssize_t)size || memcmp(value,expected,size) || close(fd)) die("exact NAND controller property differs");
}
static void physical_layout_check(void) {
    /* Linux v5.4 mtdpart.c exports the actual registered parent-relative
       offset, including command-line partitions. Never reconstruct it by
       adding sizes: the held map has a 0x780000..0x800000 gap. Linux 3.8
       without this attribute is refused; its DT labels alone are not proof.
       All partitions must directly belong to this one NAND chip, not to a
       nested MTD master whose offset would change the physical address. */
    const char *nand="/sys/firmware/devicetree/base/ocp/gpmc@50000000/nand@0,0";
    struct stat node=directory_identity(nand), parent={0};
    char path[256],value[128];
    for(unsigned i=0;i<12;i++) {
        snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/offset",i);
        text_file(path,value,sizeof(value));
        char *end; errno=0;
        unsigned long long offset=strtoull(value,&end,10);
        if(!*value || strspn(value,"0123456789")!=strlen(value) || *end || errno || offset!=parts[i].offset)
            die("exact BB physical partition offset differs");
        snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/device",i);
        struct stat current=directory_identity(path);
        if(i) same_directory(parent,current); else parent=current;
        snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/device/of_node",i);
        same_directory(node,directory_identity(path));
    }
    static const unsigned char nand_reg[12]={0};
    static const unsigned char gpmc_reg[8]={0x50,0,0,0,1,0,0,0};
    static const unsigned char ranges[16]={0,0,0,0,0,0,0,0,8,0,0,0,0x10,0,0,0};
    property("/sys/firmware/devicetree/base/ocp/gpmc@50000000/nand@0,0/reg",nand_reg,sizeof(nand_reg));
    property("/sys/firmware/devicetree/base/ocp/gpmc@50000000/reg",gpmc_reg,sizeof(gpmc_reg));
    property("/sys/firmware/devicetree/base/ocp/gpmc@50000000/ranges",ranges,sizeof(ranges));
    property("/sys/firmware/devicetree/base/ocp/gpmc@50000000/compatible",
             (const unsigned char *)"ti,am3352-gpmc",sizeof("ti,am3352-gpmc"));
}
static void layout_check(unsigned selected,int writing) {
    FILE *file=fopen("/proc/mtd","r");
    char line[512],name[256],extra,path[128],value[128];
    unsigned row=0,index,size,erase;
    if(!file || !fgets(line,sizeof(line),file) || strncmp(line,"dev:",4)) die("MTD header");
    while(fgets(line,sizeof(line),file)) {
        if(row>=12 || sscanf(line,"mtd%u: %x %x \"%255[^\"]\" %c",
            &index,&size,&erase,name,&extra)!=4 || index!=row ||
            strcmp(name,parts[row].name) || size!=parts[row].size || erase!=ERASE)
            die("exact BB partition map differs");
        row++;
    }
    if(ferror(file) || fclose(file) || row!=12) die("MTD inventory");
    physical_layout_check();
    if(!writing) return;
    text_file("/etc/dcentos/board_target",value,sizeof(value));
    if(strcmp(value,"am3-bb-s19jpro")) die("exact BB recovery target required");
    file=fopen("/proc/mounts","r");
    char source[256],mount[256],type[64],options[256];
    unsigned root_count=0;
    if(!file) die("mount inventory");
    while(fgets(line,sizeof(line),file)) {
        if(!strchr(line,'\n') || sscanf(line,"%255s %255s %63s %255s",source,mount,type,options)!=4)
            die("mount entry invalid");
        if(!strcmp(mount,"/")) {
            root_count++;
            if(strcmp(type,"rootfs") && strcmp(type,"ramfs") && strcmp(type,"tmpfs"))
                die("replace requires independent RAM recovery root");
        }
        /* Both touched partitions must be detached before either is changed.
           Resolving every allowed spelling conservatively avoids mtd aliases. */
        if(strstr(source,"mtd") || !strncmp(source,"ubi",3) || !strncmp(source,"/dev/ubi",8))
            die("NAND filesystem remains mounted");
    }
    if(ferror(file) || fclose(file) || root_count!=1) die("RAM root mount absent/ambiguous");
    for(unsigned ubi=0;ubi<32;ubi++) {
        snprintf(path,sizeof(path),"/sys/class/ubi/ubi%u/mtd_num",ubi);
        if(access(path,F_OK)) continue;
        text_file(path,value,sizeof(value));
        char *end; unsigned long attached=strtoul(value,&end,10);
        if(!*value || *end || attached==5 || attached==11 || attached==selected)
            die("destination attached to UBI or attachment is invalid");
    }
}
static void validate_env(const unsigned char *record) {
    uint32_t crc=UINT32_MAX;
    for(unsigned i=4;i<ERASE;i++) {
        crc^=record[i];
        for(unsigned bit=0;bit<8;bit++) crc=(crc>>1)^((crc&1) ? UINT32_C(0xedb88320) : 0);
    }
    uint32_t stored=record[0]|((uint32_t)record[1]<<8)|
        ((uint32_t)record[2]<<16)|((uint32_t)record[3]<<24);
    if((~crc)!=stored) die("BB environment CRC mismatch");
    for(unsigned i=4;i+1<ERASE;i++) if(!record[i] && !record[i+1]) return;
    die("BB environment has no double-NUL termination");
}
static int regular_file(const char *path,off_t min,off_t max) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat st;
    if(fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<min || st.st_size>max)
        die("bounded regular payload/backup required");
    return fd;
}
int main(int argc,char **argv) {
    int writing=argc==5 && !strcmp(argv[1],"replace");
    int reserved=argc==4 && !strcmp(argv[1],"read-reserved");
    int reading=argc==4 && (!strcmp(argv[1],"read") || reserved);
    if(!writing && !reading && !(argc==3 && !strcmp(argv[1],"check"))) {
        fprintf(stderr,"usage: am3-bb-nand-window check mtdN | read|read-reserved mtdN FILE | replace mtd5|mtd11 EXPECTED_BEFORE NEW\n");
        return 64;
    }
    unsigned selected=12;
    for(unsigned i=0;i<12;i++) {
        char name[16]; snprintf(name,sizeof(name),"mtd%u",i);
        if(!strcmp(argv[2],name)) selected=i;
    }
    if(selected==12 || (writing && selected!=5 && selected!=11)) die("window is read-only or unknown");
    if(geteuid()) die("root required");
    layout_check(selected,writing);
    char path[128],value[128],extra;
    snprintf(path,sizeof(path),"/dev/mtd%u",selected);
    int fd=open(path,(writing ? O_RDWR : O_RDONLY)|O_CLOEXEC|O_NOFOLLOW);
    struct stat st; struct mtd_info_user info;
    if(fd<0 || fstat(fd,&st) || !S_ISCHR(st.st_mode) || ioctl(fd,MEMGETINFO,&info) ||
       info.type!=MTD_NANDFLASH || info.size!=parts[selected].size ||
       info.erasesize!=ERASE || info.writesize!=PAGE) die("MTD device geometry");
    if(flock(fd,(writing ? LOCK_EX : LOCK_SH)|LOCK_NB)) die("NAND owner busy");
    snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/name",selected);
    text_file(path,value,sizeof(value));
    if(strcmp(value,parts[selected].name)) die("MTD device label differs");
    snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/dev",selected);
    text_file(path,value,sizeof(value));
    unsigned maj,min;
    if(sscanf(value,"%u:%u%c",&maj,&min,&extra)!=2 ||
       major(st.st_rdev)!=maj || minor(st.st_rdev)!=min) die("MTD device identity");
    for(uint32_t block=0;block<info.size;block+=ERASE) {
        int64_t position=block;
        if(ioctl(fd,MEMGETBADBLOCK,&position)) die("fixed window contains a bad/unknown block");
    }
    unsigned char page[PAGE],expected[PAGE];
    if(reading) {
        int out=open(argv[3],O_WRONLY|O_CLOEXEC|O_NOFOLLOW|(reserved ? 0 : O_CREAT|O_EXCL),0600);
        if(out<0) die("new backup file required");
        struct stat backup;
        if(fstat(out,&backup) || !S_ISREG(backup.st_mode) || backup.st_uid ||
           backup.st_nlink!=1 || (backup.st_mode&0777)!=0600 ||
           (reserved && (backup.st_size!=(off_t)info.size || (uint64_t)backup.st_blocks*512<info.size)))
            die("exact allocated private capture file required");
        /* Reserved capture never truncates, unlinks or frees extents. All
           logical lengths remain the exact selected partition size. */
        for(uint32_t pos=0;pos<info.size;pos+=PAGE) {
            transfer(fd,page,PAGE,pos,0); transfer(out,page,PAGE,pos,1);
        }
        if(fsync(out) || close(out)) die("backup durability failed");
    }
    if(writing) {
        int before=regular_file(argv[3],info.size,info.size);
        int after=regular_file(argv[4],selected==5 ? ERASE : 1,info.size);
        struct stat payload_stat;
        if(fstat(after,&payload_stat)) die("payload stat");
        size_t length=(size_t)payload_stat.st_size;
        size_t padded=(length+PAGE-1)/PAGE*PAGE;
        unsigned char *payload=malloc(padded);
        if(!payload) die("payload allocation");
        memset(payload,255,padded); transfer(after,payload,length,0,0);
        if(selected==5) validate_env(payload);
        if(close(after)) die("payload close");
        /* Compare the whole captured partition while holding its owner lock.
           A stale/wrong-unit backup never becomes write authority. */
        for(uint32_t pos=0;pos<info.size;pos+=PAGE) {
            transfer(before,expected,PAGE,pos,0); transfer(fd,page,PAGE,pos,0);
            if(memcmp(page,expected,PAGE)) die("destination differs from expected before-image");
        }
        if(close(before)) die("before-image close");
        layout_check(selected,1);
        snprintf(path,sizeof(path),"/dev/mtd%u",selected);
        int writer=open(path,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
        struct stat writer_stat;
        if(writer<0 || fstat(writer,&writer_stat) || !S_ISCHR(writer_stat.st_mode) ||
           writer_stat.st_rdev!=st.st_rdev || writer_stat.st_ino!=st.st_ino ||
           writer_stat.st_dev!=st.st_dev) die("MTD writer identity changed");
        for(uint32_t pos=0;pos<info.size;pos+=ERASE) {
            struct erase_info_user erase={pos,ERASE};
            if(ioctl(writer,MEMERASE,&erase)) die("erase failed; recovery required");
        }
        for(size_t pos=0;pos<padded;pos+=PAGE) transfer(writer,payload+pos,PAGE,pos,1);
        /* MTD close syncs its NAND controller; fsync is not an MTD operation. */
        if(close(writer)) die("NAND close/sync failed; recovery required");
        for(uint32_t pos=0;pos<info.size;pos+=PAGE) {
            transfer(fd,page,PAGE,pos,0);
            if(pos<padded) {
                if(memcmp(page,payload+pos,PAGE)) die("readback differs; recovery required");
            } else for(unsigned i=0;i<PAGE;i++)
                if(page[i]!=255) die("erased tail differs; recovery required");
        }
        free(payload);
    }
    if(close(fd)) die("NAND close");
    printf("state=%s\nwindow=mtd%u\nreboot_performed=false\n",
           writing ? "readback_verified" : reading ? "captured" : "checked",selected);
    return 0;
}

/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 D-Central Technologies
 * Finite physical NAND windows for the held AM2 stock8 transition.
 * No skip-bad advancement, environment write, boot selector change or reboot.
 * Capsule/identity/backup admission belongs to the calling transaction.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mtd/mtd-user.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define MIB UINT32_C(1048576)
#define ERASE UINT32_C(131072)
#define PAGE UINT32_C(2048)
struct part { const char *name; uint32_t size; };
static const struct part stock8[] = {
    {"BOOT.bin-dts-marker-kernel",40*MIB}, {"ramfs",32*MIB},
    {"configs",8*MIB}, {"sig",2*MIB}, {"reserve1",14*MIB},
    {"upgrade-ramfs",16*MIB}, {"upgrade-file",56*MIB}, {"reserve2",88*MIB}
};
static const struct part dual10[] = {
    {"boot",8*MIB}, {"boot-failover",12*MIB}, {"fpga1",2*MIB},
    {"fpga2",2*MIB}, {"uboot_env",MIB/2}, {"miner_cfg",MIB/2},
    {"recovery",87*MIB}, {"firmware1",57*MIB},
    {"firmware2",57*MIB}, {"factory",30*MIB}
};
struct window { const char *layout, *name; unsigned part; uint32_t offset, size; };
static const struct window windows[] = {
    {"stock8","transition-kernel",0,32*MIB,8*MIB},
    {"stock8","fpga-staging",4,0,1*MIB},
    {"stock8","kernel-backup",4,1*MIB,13*MIB},
    {"stock8","migration",7,1*MIB,57*MIB},
    {"stock8","factory",7,58*MIB,30*MIB},
    {"dual10","transition-kernel",6,7*MIB,8*MIB},
    {"dual10","fpga-staging",6,57*MIB,1*MIB},
    {"dual10","kernel-backup",6,58*MIB,13*MIB},
    {"dual10","migration",8,0,57*MIB},
    {"dual10","factory",9,0,30*MIB},
    {"dual10","fpga1",2,0,2*MIB},
    {"dual10","fpga2",3,0,2*MIB},
    /* Full stock replay is RAM-only and never exposes the environment record
       region to raw writes. The original first 20 MiB is read-only. */
    {"dual10","stock-boot0",0,0,8*MIB},
    {"dual10","stock-boot1",1,0,12*MIB},
    {"dual10","stock-env-tail",4,2*ERASE,2*ERASE},
    {"dual10","stock-config-tail",5,0,MIB/2},
    {"dual10","stock-boot-tail",6,0,7*MIB},
    {"dual10","stock-ramfs0",6,15*MIB,8*MIB},
    {"dual10","stock-ramfs1",6,23*MIB,8*MIB},
    {"dual10","stock-ramfs2",6,31*MIB,8*MIB},
    {"dual10","stock-ramfs3",6,39*MIB,8*MIB},
    {"dual10","stock-configs",6,47*MIB,8*MIB},
    {"dual10","stock-sig",6,55*MIB,2*MIB},
    {"dual10","stock-reserve10",6,57*MIB,MIB},
    {"dual10","stock-reserve11",6,58*MIB,8*MIB},
    {"dual10","stock-reserve12",6,66*MIB,5*MIB},
    {"dual10","stock-upgrade-ramfs0",6,71*MIB,8*MIB},
    {"dual10","stock-upgrade-ramfs1",6,79*MIB,8*MIB},
    {"dual10","stock-upgrade-file0",7,0,8*MIB},
    {"dual10","stock-upgrade-file1",7,8*MIB,8*MIB},
    {"dual10","stock-upgrade-file2",7,16*MIB,8*MIB},
    {"dual10","stock-upgrade-file3",7,24*MIB,8*MIB},
    {"dual10","stock-upgrade-file4",7,32*MIB,8*MIB},
    {"dual10","stock-upgrade-file5",7,40*MIB,8*MIB},
    {"dual10","stock-upgrade-file6",7,48*MIB,8*MIB},
    {"dual10","stock-reserve20",7,56*MIB,MIB},
    {"dual10","stock-reserve21",8,0,8*MIB},
    {"dual10","stock-reserve22",8,8*MIB,8*MIB},
    {"dual10","stock-reserve23",8,16*MIB,8*MIB},
    {"dual10","stock-reserve24",8,24*MIB,8*MIB},
    {"dual10","stock-reserve25",8,32*MIB,8*MIB},
    {"dual10","stock-reserve26",8,40*MIB,8*MIB},
    {"dual10","stock-reserve27",8,48*MIB,8*MIB},
    {"dual10","stock-reserve28",8,56*MIB,MIB},
    {"dual10","stock-reserve29",9,0,8*MIB},
    {"dual10","stock-reserve210",9,8*MIB,8*MIB},
    {"dual10","stock-reserve211",9,16*MIB,8*MIB},
    {"dual10","stock-reserve212",9,24*MIB,6*MIB}
};
static void die(const char *message) {
    fprintf(stderr,"am2-nand-window: %s (errno=%d)\n",message,errno);
    exit(1);
}
static void text_file(const char *path, char *out, size_t size) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) die("identity file open");
    ssize_t got=read(fd,out,size-1);
    if(got<=0 || got==(ssize_t)size-1) die("identity file size");
    out[got]='\0';
    if(out[got-1]=='\n') out[got-1]='\0';
    if(close(fd)) die("identity file close");
}
static void layout_check(const struct part *parts, unsigned count, const struct window *window,
                         int environment_verification) {
    FILE *file=fopen("/proc/mtd","r");
    char line[512], name[256], path[128], observed[256], extra;
    unsigned index, size, erase, row=0;
    if(!file || !fgets(line,sizeof(line),file) || strncmp(line,"dev:",4))
        die("partition header");
    while(fgets(line,sizeof(line),file)) {
        if(row>=count || sscanf(line,"mtd%u: %x %x \"%255[^\"]\" %c",
                                 &index,&size,&erase,name,&extra)!=4 ||
           index!=row || size!=parts[row].size || erase!=ERASE ||
           strcmp(name,parts[row].name)) die("partition map differs");
        snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/name",row);
        text_file(path,observed,sizeof(observed));
        if(strcmp(observed,parts[row].name)) die("MTD name differs");
        snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/size",row);
        text_file(path,observed,sizeof(observed));
        if(strtoul(observed,NULL,10)!=size) die("MTD size differs");
        snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/erasesize",row);
        text_file(path,observed,sizeof(observed));
        if(strtoul(observed,NULL,10)!=ERASE) die("MTD erase differs");
        row++;
    }
    if(ferror(file) || row!=count || fclose(file)) die("partition inventory");
    text_file("/proc/cmdline",line,sizeof(line));
    char *slot=strstr(line,"ubi.mtd=");
    if(slot) {
        /* Only the O_RDONLY redundant-environment verifier may inspect mtd4
           from a native boot. The generic writer still admits only the
           opposite FPGA; all stock/recovery windows require a RAM boot. */
        if(count!=10 || (slot!=line && slot[-1]!=' ') || strstr(slot+1,"ubi.mtd=") ||
           (slot[8]!='7' && slot[8]!='8') || (slot[9]!='\0' && slot[9]!=' '))
            die("native boot selector differs");
        if(environment_verification) {
            if(window->part!=4 || window->offset!=0 || window->size!=2*ERASE)
                die("read-only environment window differs");
        } else if((window->part!=2 && window->part!=3) ||
                  slot[8]!=(window->part==2 ? '8' : '7'))
            die("window is not the inactive FPGA or recovery RAM boot");
    }
    /* Refuse mounted UBI destinations, even with a RAM root. A caller must
       stop the exact stock services and detach the relevant reserve device. */
    for(unsigned ubi=0;ubi<32;ubi++) {
        snprintf(path,sizeof(path),"/sys/class/ubi/ubi%u/mtd_num",ubi);
        if(access(path,F_OK)) continue;
        text_file(path,observed,sizeof(observed));
        unsigned attached=(unsigned)strtoul(observed,NULL,10);
        if(attached==window->part) die("transition destination attached to UBI");
    }
}
static void transfer(int fd, void *data, size_t size, off_t offset, int writing) {
    unsigned char *p=data;
    while(size) {
        ssize_t got=writing ? pwrite(fd,p,size,offset) : pread(fd,p,size,offset);
        if(got<0 && errno==EINTR && !writing) continue;
        if(got<=0) die(writing ? "bounded write failed" : "bounded read failed");
        p+=got; offset+=got; size-=(size_t)got;
    }
}
static void verify_environment_keys(unsigned char *record, const char *expected_path) {
    int expected_fd=open(expected_path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat status;
    if(expected_fd<0 || fstat(expected_fd,&status) || !S_ISREG(status.st_mode) ||
       status.st_size<0 || status.st_size>65536) die("environment expected keys file");
    size_t length=(size_t)status.st_size;
    char *expected=malloc(length+1);
    if(!expected) die("environment expected allocation");
    transfer(expected_fd,expected,length,0,0);
    if(close(expected_fd)) die("environment expected close");
    expected[length]='\0';
    char *lines[1024]; unsigned char seen[1024]={0}; unsigned count=0;
    char *start=expected;
    for(size_t i=0;i<length;i++) {
        if(expected[i]=='\0' || expected[i]=='\r') die("environment expected encoding");
        if(expected[i]=='\n') {
            if(&expected[i]==start || count==1024 || !memchr(start,'=',(size_t)(&expected[i]-start)))
                die("environment expected entry");
            expected[i]='\0'; lines[count++]=start; start=&expected[i+1];
        }
    }
    if(start!=expected+length) die("environment expected termination");
    size_t pos=5;
    while(pos<ERASE && record[pos]) {
        unsigned char *end=memchr(record+pos,'\0',ERASE-pos);
        if(!end) die("environment key termination");
        unsigned match=count;
        for(unsigned i=0;i<count;i++)
            if(!strcmp((char *)record+pos,lines[i])) {
                if(match!=count || seen[i]) die("environment duplicate key");
                match=i;
            }
        if(match==count) die("environment unexpected key");
        seen[match]=1; pos=(size_t)(end-record)+1;
    }
    if(pos>=ERASE) die("environment final termination");
    for(unsigned i=0;i<count;i++) if(!seen[i]) die("environment missing expected key");
    free(expected);
}
static int verify_environment(const char *layout, const char *expected_path) {
    int stock=!strcmp(layout,"stock8");
    if(!stock && strcmp(layout,"dual10")) die("unknown environment layout");
    const struct part *parts=stock ? stock8 : dual10;
    struct window window={layout,"environment-verification",stock ? 0 : 4,
                          stock ? 24*MIB : 0,2*ERASE};
    if(geteuid()!=0) die("root required");
    layout_check(parts,stock ? 8 : 10,&window,1);
    char path[128],identity[128];
    snprintf(path,sizeof(path),"/dev/mtd%u",window.part);
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat status;
    struct mtd_info_user info;
    if(fd<0 || fstat(fd,&status) || !S_ISCHR(status.st_mode) ||
       ioctl(fd,MEMGETINFO,&info) || info.type!=MTD_NANDFLASH ||
       info.size!=parts[window.part].size || info.erasesize!=ERASE || info.writesize!=PAGE)
        die("environment MTD geometry");
    snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/dev",window.part);
    text_file(path,identity,sizeof(identity));
    unsigned major_id,minor_id;
    if(sscanf(identity,"%u:%u",&major_id,&minor_id)!=2 ||
       major(status.st_rdev)!=major_id || minor(status.st_rdev)!=minor_id)
        die("environment MTD identity");
    unsigned char *record=malloc(ERASE);
    unsigned flags[2];
    if(!record) die("environment record allocation");
    for(unsigned copy=0;copy<2;copy++) {
        int64_t offset=window.offset+copy*ERASE;
        if(ioctl(fd,MEMGETBADBLOCK,&offset)!=0) die("environment fixed copy has bad block");
        transfer(fd,record,ERASE,offset,0);
        uint32_t crc=UINT32_MAX;
        for(unsigned byte=5;byte<ERASE;byte++) {
            crc^=record[byte];
            for(unsigned bit=0;bit<8;bit++) crc=(crc>>1)^((crc&1) ? UINT32_C(0xedb88320) : 0);
        }
        uint32_t stored=(uint32_t)record[0]|((uint32_t)record[1]<<8)|
                        ((uint32_t)record[2]<<16)|((uint32_t)record[3]<<24);
        if((~crc)!=stored) die("environment redundant-copy CRC differs");
        if(expected_path) verify_environment_keys(record,expected_path);
        flags[copy]=record[4];
    }
    free(record);
    if(close(fd)) die("environment read close");
    printf("state=redundant_environment_verified\ncopy0_flag=%u\ncopy1_flag=%u\n",flags[0],flags[1]);
    return 0;
}
int main(int argc,char **argv) {
    if(argc==3 && !strcmp(argv[1],"verify-env")) return verify_environment(argv[2],NULL);
    if(argc==4 && !strcmp(argv[1],"verify-env-keys")) return verify_environment(argv[2],argv[3]);
    if(argc==2 && !strcmp(argv[1],"lock")) {
        /* The parent shell retains this open file description after this
           child returns, so its kernel flock lasts for the whole transaction.
           This closes the held BusyBox image's missing flock-applet dependency. */
        struct stat lock_status;
        if(geteuid()!=0 || fstat(9,&lock_status) || !S_ISREG(lock_status.st_mode) ||
           lock_status.st_uid!=0 || lock_status.st_nlink!=1 ||
           (lock_status.st_mode&0777)!=0600 || flock(9,LOCK_EX|LOCK_NB))
            die("private inherited transaction lock unavailable");
        return 0;
    }
    if(argc<4 || argc>5 ||
       (strcmp(argv[1],"check") && strcmp(argv[1],"read") && strcmp(argv[1],"write")) ||
       ((!strcmp(argv[1],"check")) != (argc==4))) {
        fprintf(stderr,"usage: am2-nand-window check|read|write stock8|dual10 WINDOW [FILE]\n");
        return 64;
    }
    const struct window *window=NULL;
    for(size_t i=0;i<sizeof(windows)/sizeof(windows[0]);i++)
        if(!strcmp(argv[2],windows[i].layout) && !strcmp(argv[3],windows[i].name)) window=&windows[i];
    if(!window) die("unknown exact window");
    unsigned count=!strcmp(argv[2],"stock8") ? 8 : 10;
    const struct part *parts=count==8 ? stock8 : dual10;
    int writing=!strcmp(argv[1],"write"), reading=!strcmp(argv[1],"read");
    if(writing && (!strcmp(window->name,"stock-boot0") ||
                   !strcmp(window->name,"stock-boot1") ||
                   !strcmp(window->name,"stock-env-tail")))
        die("original FSBL and U-Boot prefix is read-only");
    if(geteuid()!=0) die("root required");
    layout_check(parts,count,window,0);
    char path[128], identity[128];
    snprintf(path,sizeof(path),"/dev/mtd%u",window->part);
    int fd=open(path,(writing ? O_RDWR : O_RDONLY)|O_CLOEXEC|O_NOFOLLOW);
    struct stat status;
    struct mtd_info_user info;
    if(fd<0 || fstat(fd,&status) || !S_ISCHR(status.st_mode) ||
       ioctl(fd,MEMGETINFO,&info)) die("MTD device open");
    if(flock(fd,(writing ? LOCK_EX : LOCK_SH)|LOCK_NB)) die("concurrent NAND operation");
    snprintf(path,sizeof(path),"/sys/class/mtd/mtd%u/dev",window->part);
    text_file(path,identity,sizeof(identity));
    unsigned major_id,minor_id;
    if(sscanf(identity,"%u:%u",&major_id,&minor_id)!=2 ||
       major(status.st_rdev)!=major_id || minor(status.st_rdev)!=minor_id ||
       info.type!=MTD_NANDFLASH || info.size!=parts[window->part].size ||
       info.erasesize!=ERASE || info.writesize!=PAGE ||
       window->offset>info.size || window->size>info.size-window->offset)
        die("MTD identity/geometry differs");
    /* Physical window offsets are the boot contract. Refuse every known bad
       block rather than skipping it into an adjacent partition window. */
    for(uint32_t block=window->offset;block<window->offset+window->size;block+=ERASE) {
        int64_t location=block;
        if(ioctl(fd,MEMGETBADBLOCK,&location)!=0) die("bad block or unreadable bad-block map in fixed window");
    }
    if(!writing && !reading) {
        printf("state=checked\nwindow=%s\noffset=%"PRIu32"\ncapacity=%"PRIu32"\n",
               window->name,window->offset,window->size);
        close(fd); return 0;
    }
    int file=open(argv[4],(writing ? O_RDONLY : O_WRONLY|O_CREAT|O_EXCL)|O_CLOEXEC|O_NOFOLLOW,0600);
    struct stat file_status;
    if(file<0 || fstat(file,&file_status) || !S_ISREG(file_status.st_mode)) die("ordinary payload file required");
    size_t length=reading ? window->size : (size_t)file_status.st_size;
    if(length==0 || length>window->size) die("payload exceeds exact window");
    size_t padded=(length+PAGE-1)/PAGE*PAGE;
    unsigned char *payload=malloc(padded), page[PAGE];
    if(!payload) die("payload allocation");
    if(writing) {
        memset(payload,0xff,padded);
        transfer(file,payload,length,0,0);
        if(fstat(file,&status) || status.st_size!=file_status.st_size ||
           status.st_mtim.tv_sec!=file_status.st_mtim.tv_sec ||
           status.st_mtim.tv_nsec!=file_status.st_mtim.tv_nsec) die("payload changed before write");
        layout_check(parts,count,window,0);
        /* mtdchar has no fsync operation: its writable close calls mtd_sync.
           Keep the original descriptor/flock alive while closing this
           independent write descriptor, then read back under the same lock. */
        snprintf(path,sizeof(path),"/dev/mtd%u",window->part);
        int writer=open(path,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
        struct stat writer_status, locked_status;
        if(writer<0 || fstat(writer,&writer_status) || fstat(fd,&locked_status) ||
           !S_ISCHR(writer_status.st_mode) ||
           writer_status.st_rdev!=locked_status.st_rdev ||
           writer_status.st_ino!=locked_status.st_ino ||
           writer_status.st_dev!=locked_status.st_dev) die("NAND writer identity changed");
        for(uint32_t block=window->offset;block<window->offset+window->size;block+=ERASE) {
            struct erase_info_user erase={block,ERASE};
            if(ioctl(writer,MEMERASE,&erase)) die("bounded erase failed");
        }
        for(size_t pos=0;pos<padded;pos+=PAGE)
            transfer(writer,payload+pos,PAGE,(off_t)window->offset+(off_t)pos,1);
        if(close(writer)) die("NAND sync/close failed");
        for(size_t pos=0;pos<window->size;pos+=PAGE) {
            transfer(fd,page,PAGE,(off_t)window->offset+(off_t)pos,0);
            if(pos<padded) {
                if(memcmp(page,payload+pos,PAGE)) die("NAND readback differs");
            } else {
                for(size_t byte=0;byte<PAGE;byte++)
                    if(page[byte]!=0xff) die("NAND erased tail readback differs");
            }
        }
    } else {
        transfer(fd,payload,length,window->offset,0);
        transfer(file,payload,length,0,1);
        if(fsync(file)) die("backup sync failed");
    }
    if(close(file) || close(fd)) die("close failed");
    free(payload);
    printf("state=%s\nwindow=%s\nbytes=%zu\nreboot_performed=false\n",
           writing ? "readback_verified" : "captured",window->name,length);
    return 0;
}

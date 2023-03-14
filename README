# Decoding the format used by Mikrotik RouterBOOT LZ77 packed wlan caldata

Wi-Fi board calibration data is needed to run Wi-Fi on modern Qualcomm wlan SoCs
In Mikrotik hardware, this is stored on NOR, within tag ID 0x16 or 0xF
of the hard config TLV store.
Over time, the format of this wlan data on newly produced hardware has
changed. From RLE encoding, to RLE, then LZOR (using a constant prefix and the
kernel decompress_lzo1x_safe function). These are detailed in [OpenWrt's
hard_config decoding platform driver][openwrt rb_hard]
With some Mikrotik ipq40xx devices (Chateau) and ipq60xx devices, the
wlan-data is packed with a LZ77 header.

[openwrt rb_hard]: https://github.com/openwrt/openwrt/blob/master/target/linux/generic/files/drivers/platform/mikrotik/rb_hardconfig.c#L483

[Download a firmware package (7.8-arm)][7.8-arm.npk], that we know uses LZ77,
then extract it with `binwalk -Me routeros-7.8-arm.npk`
[7.8-arm.npk]: https://download.mikrotik.com/routeros/7.8/routeros-7.8-arm.npk
Search for the magic text (swapped to check other endian):
```
john@john _routeros-7.8-arm.npk.extracted]$ grep -r --binary-files=text --files-with-match '77ZL' .
./squashfs-root/lib/modules/5.6.3/misc/flash.ko
[john@john _routeros-7.8-arm.npk.extracted]$ grep -r --binary-files=text --files-with-match 'LZ77' .
```
Open flash.ko in Ghidra and analyze to decompile.
Search for lz77 to find where and how the magic (or any print strings) is
used.
With this, we see that when LZ77 magic is found,
a 0x40000 byte buffer is created for the decompression output,
and that this magic is stripped, and the length adjusted for the input.
The lz77 decompresison function takes parameters (outbuf, outbuf_len, inbuf,
inbuf_len). It will return the decompressed length on success, or -1,-2,-3 on
error.
Noted the function address boundaries: 0x10000 through 0x101b0.

Unable to follow the disassembly or decompilation in Ghidra, move to emulating
and debugging the function.

Needed the appropriate arm toolchain utils for this binary. With them, used
- `objdump` to disassemble flash.ko to extract this function,
  then cleaned up that output to be able to run it through GNU as to assemble it
  This involved:
  - convert the line numbers to labels by prefixing a char. example: `4:->l_4:`
  - cut the bytes
  - comment out the branch labels `// <function_name+xx>`
  - convert the branch addresses to labels `b8 -> l_b8`
  - fix up the switch jumptable by making these .word name_of_appropriate_branch_label
  - add a label to the start of this file (decompress_lz77)
  - went through it to identify where, how, and what the registers are used
    for (debugging helped with more later)

Made a copy of the wlan data, with 77ZL magic removed as the decompress
function requires with `dd bs=1 skip=4`.

Built a main assembly file to run from, which had:
  - include an outbuf `.fill 0x40000, 1, 0xAAAAAAAA` to make it easier
    to see bytes being uncompressed
  - outbuf len `.int outbuf_len - outbuf`
  - inbuf `.incbin "wlan_data_less_magic_binary_file"`
  - inbuf_len
  - .include the processed decompress function assembly
  - setup the registers r0 through r3
    ```
	ldr r0, =outbuf
	ldr r1, =outbuf_len
	ldr r1, [r1]
    ```
  - load end label address to $lr before calling decompress_lz77
    (popped to $pc on return)
  - branch to decompress_lz77

Assemble and link this:
```
export PATH_TOOLCHAIN="/mnt/pool_ssd/code/openwrt/staging_dir/toolchain-arm_cortex-a7+neon-vfpv4_gcc-12.2.0_musl_eabi/bin"
export PREFIX_TOOLCHAIN="arm-openwrt-linux-muslgnueabi-"

tc() {
	local tool
	tool="$1"
	shift
	"$PATH_TOOLCHAIN/${PREFIX_TOOLCHAIN}$tool" $@
}


tc as decompress-runner.s -g -o decompress-runner.o
tc ld decompress-runner.o -o decompress-runner
```

Run it with user qemu:
```
qemu-arm -cpu cortex-a7 -singlestep -g 2159 decompress-runner
```

Connect to this with gdb to debug:
```
arm-none-eabi-gdb -q
# source /usr/share/gef/gef.py # if not in ~/.gdbinit
gef-remote --qemu-user --qemu-binary decompress-runner localhost 2159

set can-use-hw-watchpoints 0

si
si
continue
dump binary memory dchard-lz77-no-tag-no-magic-unlz77 0x11270 0x11270+$r0
```

Stepped through this multiple times, and also used watch on reg values and
memory addresses to start to build an understanding

Eventually used the Qiling framework to be able to build an understanding of
assembly operations, register values, and memory addresses, as the function
walked through input bits. Example: counting delta between the input bit
address, when a byte is going to be written to the output

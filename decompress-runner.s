.data

.global outbuf
outbuf:
.type outbuf,"object"
.fill 0x40000, 1, 0xAAAAAAAA //easier to see 00 being uncompressed
//.skip 0x40000
.align 4

.global outbut_len
outbuf_len:
.type outbuf_len,"object"
.int outbuf_len - outbuf
.align 4

.global inbuf_data
.type inbuf_data,"object"
inbuf_data: //wlan tag from hard_config, with LZ77 magic cut
.incbin "dchard-hard-wlan-data-no-tag-no-lz77-magic"
.align 4

.global inbuf_len
.type inbuf_len,"object"
inbuf_len:
.int inbuf_len - inbuf_data
.align 4


.text

.global _start
_start:
load_data:
	ldr	lr, =end	//store label to quit in lr,
				//popped to pc at end of decompress_lz77
	ldr	r0, =outbuf
	ldr	r1, =outbuf_len
	ldr	r1, [r1]
	ldr	r2, =inbuf_data	//load the address of inbuf_data
	ldr	r3, =inbuf_len	//load the address of inbuf_len
	ldr	r3, [r3]	//load the value of (address of inbuf_len)
	b	decompress_lz77

.include "decompress_lz77.objdump_disassm.s"

end:
	nop
	bkpt


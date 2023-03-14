// disassembled with objdump from 7.8-arm flash.ko
decompress_lz77:
	// r0 outbuf addr, r1 outbuf_len (bytes),
	// r2 inbuf addr, r3 inbuf_len (bytes)
	push	{r0, r1, r2, r4, r5, r6, r7, r8, r9, sl, fp, lr}
	lsl	r3, r3, #3	// convert inlen to bits (bytes*8)
	mov	r5, #0		// first test variable (against 0)
			// possible values of 0, or 1
			// starts as 0, set to 1 in a few places,
			// if r5 !=0,
			// 	set r5 = r6 (current input bit after r6 set)
	str	r3, [sp, #4]	// store initial inlen (bits) on stack[4]
	mov	sl, #1	// r10 match offset, set from lr
	mov	r9, r0	// const output start address
	add	r1, r0, r1	// convert to adress of end of outbuf
	mov	r3, r0	// output address cursor
	mov	ip, r5	// r12 left shift by ip |
			// temp match byte store |
			// bits left in current section
	mov	lr, r5	// r14 temp non-match byte store | temp match offset
	mov	r7, r5	// ??non-match additional bytes count. lr + 11, or r7 - 1
	mov	r4, r5	// switch-case var
	mov	r8, r5	// input bit index
	mov	fp, sl	// r11 fp const 1, for left shift ops 1<<x

	// registers summary
	// r0 tmp, used multiple places
	// r1 const address at end of outbuf
	// r2 const address of inbuf
	// r3 outbuf cursor address
	// r4 switch-case variable
	// r5 bool, tested after loading r6
		// if not set, set to r6
		// set to 1 in a number of places
	// r6 input bit value (lowest byte, lowest bit ascending)
	// r7 bytes in a non-matching group
	// r8 input bit index
	// r9 const outbuf address
	// r10|sl match offset
	// r11|fp const 1, used for 1<<x left shift ops
	// r12|ip
		// for match group byte, used for load, then store
		// set to 0, 4, or 8
		// 1<<ip left shift
		// but incremented and decremented to count len or build byte
		// bits left in current section to produce number / byte
	// r14|lr
		// used to build counts lr = lr + x
		// non-match group byte build location
		// match group length

get_input_bit: //loop_start: //l_38:
	ldrb	r6, [r2, r8, lsr #3] // load byte into r6
		// from r2 (inbuf start address) + offset
		// offset = r8 (input bit index) converted to bytes (>>3 or /8)
	and	r0, r8, #7	// r8 % 8
	cmp	r5, #0
	asr	r6, r6, r0	// right shift by (bit index % 8)
	and	r6, r6, #1	// keep only lowest bit
	beq	l_8c
	cmp	r6, #0
	mov	r5, r6
	addne	lr, lr, fp, lsl ip
	addne	ip, ip, #1	// ?non-match group long match pre-len bit set,
				// (starts at 4)
				// so test the next bit
				// continue this, until
				// an unset bit is found, then
				// the following len has this many bits
				// finally, add 11
l_60:
	cmp	ip, #0
	bne	increment_inbit_index
switch_case: //l_68:
	sub	r0, r4, #1
	cmp	r0, #4
	ldrls	pc, [pc, r0, lsl #2]
	b	case_default //l_c4
		// case jumptable
	.word	case_1 //l_f0
	.word	case_2 //l_a4
	.word	case_3 //l_124
	.word	case_4 //l_138
	.word	case_5 //l_154
l_8c:
	cmp	ip, #0
	beq	switch_case
	sub	ip, ip, #1	//non-match group len, or byte build
	cmp	r6, #0
	addne	lr, lr, fp, lsl ip //build number from SET inbit
	b	l_60
case_2: // l_a4:
	add	lr, r3, lr
	rsb	r0, sl, #0	//reverse subtract r0 = 0 - sl
store_match_or_end: // l_ac:
	cmp	r3, lr		// if not at the end of a match
	bne	store_match_byte	// write it in the outbuf
	mov	ip, #0
	mov	lr, ip //0
l_bc:
	mov	r4, ip //0	case default
	b	increment_inbit_index
case_default: // l_c4:
	cmp	r6, #0
	movne	ip, #0
	moveq	ip, #8		//8 bits (byte) for this section
	movne	r4, #1
	moveq	r4, #5
increment_inbit_index: // l_d8:
	ldr	r0, [sp, #4]
	add	r8, r8, #1
	cmp	r0, r8		// if input length(bits) > inbit_index, continue
	bcs	get_input_bit
err_1:
	mvn	r0, #0	// r0 = -1	otherwise, exit -1
	b	lz77_return
case_1: // l_f0:
	cmp	r6, #0
	mov	r5, r4
	moveq	ip, r6 //0
	moveq	lr, #1
	moveq	r4, #2		// next case2 (store match if not at match end)
	movne	ip, #4		// 4 bits for this section
	movne	r4, #3
	b	increment_inbit_index
store_match_byte: // l_110:
	cmp	r3, r1		// if cursor not > outbuf_end
	bcs	err_2
	ldrb	ip, [r3, r0]	// load match from earlier into ip
				// from r3 + (offset r0)
	strb	ip, [r3], #1	// store this match & increment r3
	b	store_match_or_end
case_3: // l_124:
	cmp	lr, #0
	bne	l_180
	mov	r5, #1
	mov	ip, #4		// 4 bits for this section
	b	l_bc
case_4: // l_138:
	cmp	lr, #0
	beq	calc_decompressed_len
	add	r7, lr, #11	// long non-match group len+=11
	mov	ip, #8		// 8 bits for this section (non-match char)
	mov	lr, #0		// so that the non-match char can be built there
	mov	r4, #5		// next case5 (store non-match)
	b	increment_inbit_index
case_5: //store a non-matching byte l_154:
	cmp	r1, r3
	bls	err_3
	cmp	r7, #0
	strb	lr, [r3], #1 //store lr value to address from r3. then r3++
	subne	r7, r7, #1
	movne	ip, #8
	movne	lr, #0
	moveq	ip, r7 //0
	moveq	lr, r7 //0
	moveq	r4, r7 //0
	b	increment_inbit_index
l_180:
	mov	sl, lr
	mov	r5, #1
	mov	lr, #2
	mov	ip, #0
	mov	r4, lr //2	case2 (store match)
	b	increment_inbit_index
calc_decompressed_len: // l_198:
	sub	r0, r3, r9
lz77_return: // l_19c:
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r9, sl, fp, pc}
err_2: // l_1a4:
	mvn	r0, #1	// r0 = -2
	b	lz77_return
err_3: // l_1ac:
	mvn	r0, #2	// r0 = -3
	b	lz77_return

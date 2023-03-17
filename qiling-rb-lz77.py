from pathlib import Path
import struct

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.exception import QlErrorCoreHook

from collections import Counter


#rootfs = Path("/tmp/venv-qiling/_routeros-7.8-arm64.npk.extracted/squashfs-root")
rootfs = Path("/tmp/venv-qiling/_routeros-7.8-arm.npk.extracted/squashfs-root")
file = rootfs / "lib/modules/5.6.3/misc/flash.ko"
file = Path("/tmp/venv-qiling/arm-test")
compressed_file = Path("/home/john/mikrotik/OEM/chateau12/dchard-mtd2-hard-config-chateau12-2")

fp = open(compressed_file, "rb")
hard_tags_data = fp.read()
fp.close()

#lz77_decomp_function_start_address=0x34
#lz77_decomp_function_end_address=0x34+0x1b0


from unicorn.unicorn_const import UC_MEM_WRITE,UC_PROT_READ

from capstone import Cs
from capstone.arm_const import ARM_INS_LDRB,ARM_INS_STRB,ARM_INS_POP,ARM_INS_PUSH

from qiling.arch.arm_const import reg_map

hide_regs = ['cpsr', 'c1_c0_2', 'c13_c0_3', 'fpexc']
hide_regs.append('r1') # don't need const outbuf end address
hide_regs.append('r2') # don't need const inbuf address
hide_regs.append('r9') # don't need const outbuf start address
hide_regs.append('r11') # don't need const 1

reg_names = [key for key in reg_map.keys() if key not in hide_regs ]
previous_regs = None
reg_differences = None

previous_inputbit = None

write_outbit_from_inbit = []

uncompressed_data = None

# from readelf -a arm-test
block_addresses = {}
block_addresses[0x10074] = 'load_data'
block_addresses[0x10094] = 'decompress_lz77'
block_addresses[0x100cc] = 'get_input_bit'
block_addresses[0x10120] = 'l_8c'
block_addresses[0x100f4] = 'l_60'
block_addresses[0x1016c] = 'input_bit_index++'
block_addresses[0x100fc] = 'switch_case'
block_addresses[0x10138] = 'case2'
block_addresses[0x10140] = 'store_match_or_end_match'
block_addresses[0x10150] = 'l_bc'
block_addresses[0x10158] = 'case_default'
block_addresses[0x10184] = 'case1'
block_addresses[0x101a4] = 'store_match_byte'
block_addresses[0x101b8] = 'case3'
block_addresses[0x101cc] = 'case4'
block_addresses[0x101e8] = 'case5'
block_addresses[0x10214] = 'l_180'
block_addresses[0x1022c] = 'calc_decompressed_len'
block_addresses[0x10230] = 'lz77_decompress_return'
block_addresses[0x1017c] = 'err_1'
block_addresses[0x10238] = 'err_2'
block_addresses[0x10240] = 'err_3'
block_addresses[0x11270] = 'outbuf'
block_addresses[0x51270] = 'outbuf_len'
block_addresses[0x51280] = 'inbuf'
block_addresses[0x51d40] = 'inbuf_len'


def get_hardtag(hard_config: bytes, tag_id: int) -> bytes:
    i = 0
    if not hard_config[i:i+4] == b'Hard':
        return b''

    while True:
        i += 4
        if i + 4 > len(hard_config):
            return b''
        current_len_tag = struct.unpack("<I", hard_config[i:i+4])[0]
        current_tag_len = current_len_tag >> 0x10
        current_tag_id = current_len_tag & 0xff

        if current_tag_id == tag_id:
            return hard_config[i+4:i+4+current_tag_len]

        i += current_tag_len

def name_block(address):
    # not working...
    #return ''
    block = [block_addr for block_addr in sorted(block_addresses.keys())
             if block_addr <=address][-1]
    return block_addresses[block]

def dump_regs(ql: Qiling, diff=False):
    regs = [eval(f'ql.arch.regs.{key}') for key in reg_names]
    regd = dict(zip(reg_names, regs))
    global previous_regs, reg_differences
    if previous_regs is not None and diff:
        reg_differences = set(regd.items()) - set(previous_regs.items())
    previous_regs = regd
    regs_string = ', '.join([f'{reg}: {value:#x}' for (reg,value) in regd.items()])
    ql.log.debug(f'{regs_string} block:{name_block(ql.arch.regs.pc)}')
    if reg_differences is not None and diff:
        diff_string = ", ".join([f'{reg}: {value:#x}' for (reg,value) in iter(reg_differences) if reg not in 'pc'])
        if len(diff_string) > 1:
            ql.log.debug(diff_string)

def dump_reg_info(ql: Qiling):
    global write_outbit_from_inbit
    write_outbit_from_inbit.append(ql.arch.regs.r8)

    if ql.arch.regs.r4 == 5:
        matched = False
        # case 5, write non-matching byte
        # byte is built in lr (r14) before writing
        additional_nonmatched_bytes = ql.arch.regs.r7
        pass
    elif ql.arch.regs.r4 == 2:
        matched = True
        # case 2, write matched byte
        # byte is loaded to ip (r12) before writing
        # offset from match start is in sl (r10)
        # lr is the output address after match ends
        match_start_offset = -ql.arch.regs.r10
        match_finished_address = ql.arch.regs.lr
        match_len_remaining = match_finished_address - ql.arch.regs.r3
        pass

    global previous_inputbit
    inputbit_diff_str = None

    if previous_inputbit is not None:
        inputbit_diff = ql.arch.regs.r8 - previous_inputbit
        inputbit_diff_str = f'+{inputbit_diff:#x} bits from last.'
    previous_inputbit = ql.arch.regs.r8

    ql.log.debug(   f'->{ql.arch.regs.r8:#x} (input bit) {inputbit_diff_str}'
                    # on byteswapped, reversed BitStream b of inbuf:
                    # b[r8-7:r8+1] == outvalue
                    f' byte[bit]: {ql.arch.regs.r8//8:#x}[{ql.arch.regs.r8%8}]')


    infostr = f'+non' if not matched else ''
    infostr += '-matched'
    infostr += f' {additional_nonmatched_bytes:#x} extras left after this byte' if not matched else ''
    infostr += f' start offset {match_start_offset:#x}' if matched else ''
    infostr += f' len remaining {match_len_remaining:#x}' if matched else ''

    ql.log.debug(   infostr)

def dump_uncompressed(ql: Qiling):
    r0 = ql.arch.regs.r0
    return_code = struct.unpack("<i", struct.pack("<I", r0))[0]
    if return_code <= 0:
        ql.log.debug(f'decompress_lz77 failed, returned: {return_code:#x}')
        return None

    uncompressed_len = return_code
    uncompressed_end = ql.arch.regs.r3

    uncompressed_start = uncompressed_end - uncompressed_len
    ql.log.debug(f'payload in mem {uncompressed_start:#x} ({uncompressed_len:#x} bytes)')

    uncompressed_payload = ql.mem.read(uncompressed_start, uncompressed_len)
    return uncompressed_payload

def hook_decompress_entry(ql: Qiling):
    wlan_tag = get_hardtag(hard_tags_data, 0x16)
    wlan_data_ptr = ql.mem.map_anywhere((len(wlan_tag)+4//0x1000*0x1000), minaddr=ql.os.entry_point, perms=UC_PROT_READ, info="compressed_wlan_data")
    ql.mem.write(wlan_data_ptr, wlan_tag)

    for info_line in ql.mem.get_formatted_mapinfo():
      ql.log.info(info_line)


    ql.log.debug(f'current regs: r2 {ql.arch.regs.r2:#x} (inbuf_ptr) r3 {ql.arch.regs.r3:#x} (inbuf_len)')
    ql.arch.regs.r2 = wlan_data_ptr + 4
    ql.arch.regs.r3 = len(wlan_tag) - 4


def hook_pop(ql: Qiling):
    ql.log.debug(f'hooked pop')
    uncompressed_data = dump_uncompressed(ql)

def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    buf = ql.mem.read(address, size)

    for insn in md.disasm(buf, address):
        if insn.id in [ARM_INS_PUSH]:
            hook_decompress_entry(ql)

    return

    input_bit_start = None
    input_bit_end = None

    # second match group

    # long non-match 1
    input_bit_start = 0x5ad+1
    input_bit_end = 0x5c6+7

    # very long non-match (91+ bytes)
    input_bit_start = 0x1a35
    input_bit_end = 0x1a4f

    # input bit index > first match < second match
    # see how 1st match group offset, length is built
    input_bit_start = 0xcb
    input_bit_end = 0xdd

    # build first non-match group len (assume first group is non-match?)
    input_bit_start = 0x0
    input_bit_end = 0x20

    # first 0b10 match group
    input_bit_start = 0x148
    input_bit_end = 0x160

    input_bit_start = 0x2df-20
    input_bit_end = 0x2df+10

    input_bit_start = 0x55ea
    input_bit_end = 0xffff

    if (input_bit_start is not None and ql.arch.regs.r8 >= input_bit_start and
        input_bit_end is not None and ql.arch.regs.r8 <= input_bit_end):
        pass
    else:
        return

    # skip register load pre decompress
    if ql.arch.regs.pc < 0x10094:
        return

    # skip register setup pre first bit load
    if ql.arch.regs.pc < 0x100cc:
        return

    for insn in md.disasm(buf, address):
        #if insn.id in (ARM_INS_LDRB, ARM_INS_STRB):
        if True:
            dump_regs(ql, diff=True)
            ql.log.debug(f':: {insn.id:#x} {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}')
        #if insn.id in [ARM_INS_POP]:
        #    hook_pop(ql)

def mem_write(ql: Qiling, access: int, address: int, size: int, value: int, context) -> None:
    # only write accesses are expected here
    assert access == UC_MEM_WRITE

    # find non-match > 0x5a long
    if ql.arch.regs.r7 < 0x5a:
        # occurs for outbyte 0x641 written at inbit 0x1af4
        pass

    start_addr = None
    break_addr = None

    start_addr = 0
    break_addr = 0x1b
    #start_addr = 0x17
    #break_addr = 0x1f
    #break_addr = 0x60
    #break_addr = 0x60

    # long non-match 1
    #start_addr = 0x115
    #break_addr = 0x120

    # long non-match 91+
    #start_addr = 0x641-3
    #break_addr = 0x643

    # 0b10 match group 1
    start_addr = 0x28
    break_addr = 0x2d

    start_addr = 0x2d7//8-1
    break_addr = 0x318//8+1

    # how to end?
    start_addr = 0x2e90
    break_addr = None

    if start_addr is not None and address < 0x11270+start_addr:
        return

    if ql.arch.regs.lr == value:
        lr_eq_out = True
    if ql.arch.regs.r12 == value:
        r12_eq_out = True

    dump_reg_info(ql)
    ql.log.debug(   f'<-outbuf[{address-0x11270:#x}]={value:#x}')

    if break_addr is not None and address > 0x11270+break_addr:
        ql.emu_stop()



if __name__ == "__main__":
    ql = Qiling([str(file)], str(rootfs), verbose=QL_VERBOSE.DEBUG)

    start_address=0x11270
    address_len=0x40000

    ql.hook_mem_write(mem_write, "", start_address, start_address+address_len)

    ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)

    # does not work
    #ql.hook_insn(hook_pop, ARM_INS_POP)


    #ql.run(begin=lz77_decomp_function_start_address, end=lz77_decomp_function_end_address)
    try:
        ql.run()
    except QlErrorCoreHook as ex:
        pass

    #global write_outbit_from_inbit
    inbits_outlist = write_outbit_from_inbit
    inbits_outlist_deltas = [ d2 - d1 for d1, d2 in
                             zip(inbits_outlist, inbits_outlist[1:])]
    inbits_outlist_deltas_counts = Counter(inbits_outlist_deltas)
    ql.log.info(f'Input bit when output bit written'
                f' delta between this write inbit,'
                f' and previous write inbit')
    ql.log.info(f'Counts of inbit (at outbyte write) delta occurances:')
    ql.log.info(f'{inbits_outlist_deltas_counts}')
    ql.log.info(f'List of inbit (at outbyte write) delta occurances:')
    ql.log.info(f'{dict(sorted(inbits_outlist_deltas_counts.most_common()))}')

    # still have memory contents after run complete
    # and regs r0 and r1 are not changed
    uncompressed_data = dump_uncompressed(ql)

    ql.log.info(f'qiling mem dumped uncompressed payload len {len(uncompressed_data):#x}')
    ql.log.info(f'{" ".join(hex(b) for b in uncompressed_data[0:32])}')

    fn = "output-decompressed-qiling"
    fp = open(fn, "wb")
    fp.write(uncompressed_data)
    fp.close()

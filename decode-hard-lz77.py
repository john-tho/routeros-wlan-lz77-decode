import bitstring
import struct
import argparse
import logging
import errno
import os
from pathlib import Path

parser = argparse.ArgumentParser(description="Decode Mikrotik lz77 wlan hard cfg")
parser.add_argument("input",
                    type=Path, help="binary hardconfig dump path")
parser.add_argument("--out", type=Path, help="lz77 decoded wlan output path",
                    dest="output")
parser.add_argument("--force", help="overwrite existing file",
                    default=False, action="store_true")
parser.add_argument("--loglevel", choices=logging._nameToLevel.keys(),
                    help="log level", default="INFO")

args = parser.parse_args()
logging.basicConfig(level=args.loglevel)

if not args.input.is_file():
    raise IOError(errno.ENOENT,
                  os.strerror(errno.ENOENT),
                  args.input)

if args.output is None:
    args.output = Path(str(args.input) + "-lz77-decoded")
    logging.info(f"output to: {args.output}")

def get_hardtag(hard_config: bytes, tag_id: int) -> (int, int):
    i = 0
    if not hard_config[i:i+4] == b'Hard':
        logging.critical("input missing Hardcfg start tag")
        return (-1, 0)

    while True:
        i += 4
        if i + 4 > len(hard_config):
            raise IOError(errno.EINVAL,
                          "input file too short, or not valid hardcfg",
                          args.input)
            return (-1, 0)

        current_len_tag = struct.unpack("<I", hard_config[i:i+4])[0]
        current_tag_len = current_len_tag >> 0x10
        current_tag_id = current_len_tag & 0xff
        logging.debug("hard tag walk:" +
                      f" hard_tag id:{current_tag_id:#x}" +
                      f" len:{current_tag_len:#x}")

        if current_tag_id == tag_id:
            logging.info("hard tag requested found:" +
                         f" data offset:{i+4:#x}" +
                         f" len:{current_tag_len:#x}")
            return (i+4,current_tag_len)

        i += current_tag_len

    raise IOError(errno.EINVAL,
                  "input file does not contain requested hardcfg tag" +
                  f" {tag_id}",
                  args.input)
    return (-1,0)

def decode_count(bits, counter_start_index, starting_shift):
  count = 0
  index = counter_start_index
  # offset and non-byte-group-len counts start from <<4
  # match len counts start from <<0
  shift = starting_shift
  while bits[index] == 1:
    # increment the shift until reaching a zero bit
    count += (1 << shift)
    index += 1
    shift += 1
  # then the following (shift) bits are added by decrementing the shift
  index += 1
  if shift > 0:
    count += bits[index:index+shift].uint
  # need to know the count, and how many bits it took to calculate
  return (count, index + shift - counter_start_index)


def decode_op(bits, op_start_index):
  index = op_start_index
  op = None
  bit = bits[index]
  if bit == 0:
    # 0b0 non-match single byte
    op = 0
    index += 1
    return (op, index - op_start_index, 0, 1)
  else:
    index += 1
    bit = bits[index]
    index += 1
    if bit == 0:
      # 0packed_lz77_wlan_data0 match group using previous offset
      # counter starts at <<0, and is = match_length - 1
      op = 2
      (count2,count2_len) = decode_count(bits, index, 0)
      index+=count2_len
      match_len = 1 # built-in match length of 1
      match_len += count2
      return (op, index - op_start_index, 0, match_len)
    elif bit == 1:
      # 0packed_lz77_wlan_data1 counter starts at <<4
      op = 3
      (count1,count1_len) = decode_count(bits, index, 4)
      index += count1_len
      if count1 == 0:
        # if count1 == 0, non-match group
        # count2 starts at <<4 and is the non-match bytes following - 11 - 1
        op = 4
        (count2,count2_len) = decode_count(bits, index, 4)
        count2 += 11 # built-in minimum for this case
        count2 += 1 # plus zeroth byte
        index += count2_len
        return (op, index - op_start_index, count1, count2)
      elif count1 > 0:
        # if count1 > 0, match group offset-1 = count1
        # count2 starts at <<0 and is the match length - 2
        match_len = 2 # built-in match length of 2
        (count2,count2_len) = decode_count(bits, index, 0)
        index += count2_len
        match_len += count2
        return (op, index - op_start_index, count1, match_len)
        #   op, bits used by op+counters, offset bytes, len bytes


def decode_lz77(out, b):
  i = 0
  previous_offset = 0
  while i < b.len:
    op = decode_op(b,i)
    i += op[1]
    if op[0] == 4:
      bitcount=op[3]*8
      append_bits=b[i:i+bitcount]
      #decode_op op4 returns (op, index - op_start_index, count1, count2)
      if bitcount//8 == 12:
        # len 12 minimum after built-in additions
        logging.info("lz77 decode may be finished" +
                     f", append len: {append_bits.len}" +
                     f", append bit: {append_bits}")
        # 0 bit as final
        if '0b0'*append_bits.len == append_bits:
          logging.debug(f"inbit{i-1:#x}->outbyte{(out.len-1)//8:#x} {op}")
          logging.info("lz77 decode finished" +
                       f", uncompressed length: {out.len//8:x}")
          return
      out.append(append_bits)
      i += bitcount
    if op[0] == 0:
      bitcount = 1 * 8
      append_bits = b[i:i+bitcount]
      out.append(append_bits)
      i += bitcount
    if op[0] in (2,3):
      out_cursor=out.len
      match_offset = previous_offset
      if op[0] == 3:
        match_offset=op[2]
        previous_offset = match_offset
      match_pos = out_cursor - (8 * match_offset)
      match_len = op[3] * 8
      matched_bits=out[match_pos:match_pos+match_len]
      out.append(matched_bits)
      # cannot always do this in bulk,
      # because at times the match char is part of the match group
      while True:
        current_end = out.len - 8
        match_expected_end = out_cursor - 8 + match_len
        match_missed = match_expected_end - current_end
        if match_missed == 0:
          break
        new_match_pos = match_pos + match_len - match_missed
        new_match_len = match_missed
        new_matched_bits = out[new_match_pos:new_match_pos+new_match_len]
        out.append(new_matched_bits)
        matched_bits.append(new_matched_bits)
    # last bit at input to write byte to out[outbyte]
    # (opcode, bits used by opcode and count
    #   for 4 and 0: 0, group non-matching-bytes-count)
    #   for 3: match offset, match len)
    logging.debug(f"inbit{i-1:#x}->outbyte{(out.len-1)//8:#x} {op}")

  logging.info("final bit decode at bytes:" +
               f" input: {(i-1)//8:#x}"
               f" output: {(out.len-1)//8:#x}")

fn=args.input
fp=open(fn, "rb")
data1=fp.read()
fp.close()

(wlan_tag_index, wlan_tag_len) = get_hardtag(data1, 0x16)
wlan_tag = data1[wlan_tag_index:wlan_tag_index+wlan_tag_len]
if not len(wlan_tag) == wlan_tag_len:
    raise IOError(errno.EINVAL,
                  "input file too short, stops before end of wlan tag",
                  args.input)

wlan_tag_nomagic = wlan_tag[4:]

packed_lz77_wlan_data = bitstring.BitStream(wlan_tag_nomagic)
packed_lz77_wlan_data.byteswap()
packed_lz77_wlan_data.reverse()

unpacked_lz77_wlan_data = bitstring.BitStream()
decode_lz77(unpacked_lz77_wlan_data,packed_lz77_wlan_data)
logging.info("lz77 packed is" +
             f" {len(packed_lz77_wlan_data)/len(unpacked_lz77_wlan_data):.4f} unpacked")

expected_unpacked_start = bitstring.BitArray(bytes=b"DRE\x00")
if expected_unpacked_start == unpacked_lz77_wlan_data[0:4*8]:
    logging.info(f"unpacked[0:4]: matches expected DRE\\x00")
else:
    logging.warning("unpacked[0:4]: unexpected: " +
                    f" decode error?: {unpacked_lz77_wlan_data[0:4*8]}")

if args.output.is_file() and not args.force:
    raise IOError(errno.EEXIST,
                  os.strerror(errno.EEXIST),
                  args.input)

fn=args.output
fp=open(fn, "wb")
fp.write(unpacked_lz77_wlan_data.tobytes())
fp.close()



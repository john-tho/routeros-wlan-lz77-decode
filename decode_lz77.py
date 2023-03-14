import bitstring

fn="dchard-hard-wlan-data-no-tag-no-lz77-magic"
fp=open(fn, "rb")
data=fp.read()
fp.close()

fn="dchard-hard-wlan-data-no-tag-no-lz77-magic-unlz77-qemu"
fp=open(fn, "rb")
udata=fp.read()
fp.close()

a = bitstring.BitStream(udata)
b = bitstring.BitStream(data)
b0 = bitstring.BitStream(data)

# because lz77 decompress reads from lowest bit to highest
b.byteswap()
b.reverse()

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
      # 0b10 match group using previous offset
      # counter starts at <<0, and is = match_length - 1
      op = 2
      (count2,count2_len) = decode_count(bits, index, 0)
      index+=count2_len
      match_len = 1 # built-in match length of 1
      match_len += count2
      return (op, index - op_start_index, 0, match_len)
    elif bit == 1:
      # 0b11 counter starts at <<4
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
      if bitcount//8 == 12 and append_bits.len == 1 and append_bits == '0b0':
        # len 12 minimum after built-in additions, 0 bit as final
        print(f'finished. uncompressed length: {out.len//8:#x}')
        return
      out.append(append_bits)
      i += bitcount
    if op[0] == 0:
      bitcount = 1 * 8
      append_bits =b [i:i+bitcount]
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
    print(f'inbit{i-1:#x}->outbyte{(out.len-1)//8:#x} {op}')

out = bitstring.BitStream()
decode_lz77(out,b)

print(f'uncompress matches emulated result?: {out == a}')

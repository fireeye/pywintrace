########################################################################
# Copyright 2017 FireEye Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
########################################################################

import argparse
import base64
import binascii
import xml.dom.minidom
import array
import ctypes as ct
import struct


INVALID_SYMBOL = 0xFFFF
CHUNK_SIZE = 0x10000
STREAM_END = 0x100
SYMBOLS = 0x200
HALF_SYMBOLS = 0x100
HUFF_BITS_MAX = 15
MIN_DATA = HALF_SYMBOLS + 4


def get_uint_16(data):
    return struct.unpack_from('<H', data)[0]


def get_uint_32(data):
    return struct.unpack_from('<L', data)[0]


def list_in_range(data, idx):
    return 0 <= idx < len(data)


class InputBitstream:
    '''
    Input stream class. Based on ms-compress https://github.com/coderforlife/ms-compress
    '''
    def __init__(self, in_data):
        self.in_data = in_data[4:]
        self.in_len = len(in_data)
        self.mask = ct.c_uint32((get_uint_16(in_data) << 16) | get_uint_16(in_data[2:]))
        self.bits = ct.c_uint32(32)

    def raw_stream(self):
        return self.in_data

    def available_bits(self):
        return self.bits.value

    def remaining_raw_bytes(self):
        return len(self.in_data)

    def peek(self, n):
        return (self.mask.value >> 16) >> (16 - n)

    def mask_is_zero(self):
        return self.bits.value == 0 or (self.mask.value >> (32 - self.bits.value)) == 0

    def skip(self, n):
        self.mask.value <<= n
        self.bits.value -= n
        if (self.bits.value < 16) and (len(self.in_data) + 2 <= self.in_len):
            self.mask.value |= get_uint_16(self.in_data) << (16 - self.bits.value)
            self.bits.value |= 0x10
            self.in_data = self.in_data[2:]

    def read_bits(self, n):
        x = self.peek(n)
        self.skip(n)
        return x

    def read_raw_byte(self):
        ret = self.in_data[0]
        self.in_data = self.in_data[1:]
        return ret

    def read_raw_uint16(self):
        x = get_uint_16(self.in_data)
        self.in_data = self.in_data[2:]
        return x

    def read_raw_uint32(self):
        x = get_uint_32(self.in_data)
        self.in_data = self.in_data[4:]
        return x


class HuffmanDecoder:
    '''
    Decodes data encoded using Huffman coding. Based on ms-compress https://github.com/coderforlife/ms-compress
    '''
    num_bits_max = ct.c_uint32(15)
    num_symbols = ct.c_uint32(512)
    num_table_bits = ct.c_uint32(int((num_bits_max.value + 1) / 2 + 1))

    def __init__(self):
        self.lims = []
        [self.lims.append(0) for _ in range(self.num_bits_max.value + 1)]

        self.poss = []
        [self.poss.append(0) for _ in range(self.num_bits_max.value + 1)]

        self.syms = []
        [self.syms.append(0) for _ in range(self.num_symbols.value)]

        self.lens = []
        [self.lens.append(0) for _ in range(1 << self.num_table_bits.value)]

    def set_code_lengths(self, code_lengths):

        for i in range(len(self.syms)):
            self.syms[i] = INVALID_SYMBOL

        cnts = []
        [cnts.append(0) for _ in range(self.num_bits_max.value + 1)]

        for s in range(self.num_symbols.value):
            cnts[code_lengths[s]] += 1
        cnts[0] = 0

        max_value = ct.c_uint16(1 << self.num_bits_max.value)

        last = 0
        index = 0
        self.lims[0] = 0
        self.lims[self.num_bits_max.value] = max_value.value

        for length in range(1, self.num_table_bits.value + 1):
            inc = cnts[length] << (self.num_bits_max.value - length)
            if (last + inc) > max_value.value:
                return False

            last += inc
            self.lims[length] = last

            limit = last >> (self.num_bits_max.value - self.num_table_bits.value)

            for i in range(limit - index):
                self.lens[index + i] = length
            index = limit

        for length in range(self.num_table_bits.value + 1, self.num_bits_max.value):
            inc = cnts[length] << (self.num_bits_max.value - length)

            if (last + inc) > max_value.value:
                return False

            last += inc
            self.lims[length] = last

        if (last + cnts[self.num_bits_max.value]) > max_value.value:
            return False

        self.poss[0] = 0

        for length in range(1, self.num_bits_max.value + 1):
            self.poss[length] = self.poss[length - 1] + cnts[length - 1]

        for i in range(len(self.poss)):
            cnts[i] = self.poss[i]

        for s in range(self.num_symbols.value):
            length = code_lengths[s]
            if length:
                self.syms[cnts[length]] = s
                cnts[length] += 1
        return True

    def decode_symbol(self, input_stream_bits):
        n = 0
        r = input_stream_bits.available_bits()

        x = ct.c_uint32(0)
        if r < self.num_bits_max.value:
            x.value = ct.c_uint32(input_stream_bits.peek(r) << (self.num_bits_max.value - r))
        else:
            x = ct.c_uint32(input_stream_bits.peek(self.num_bits_max.value))

        if x.value < self.lims[self.num_table_bits.value]:
            n = self.lens[x.value >> (self.num_bits_max.value - self.num_table_bits.value)]
        else:
            n = self.num_table_bits.value + 1
            while x.value >= self.lims[n]:
                n += 1

        if n > r:
            return INVALID_SYMBOL

        input_stream_bits.skip(n)

        s = self.poss[n] + \
            (ct.c_uint32(x.value - self.lims[n - 1]).value >> ct.c_uint32(self.num_bits_max.value - n).value)
        return INVALID_SYMBOL if (s >= self.num_symbols.value) else self.syms[s]


def xpress_huff_decompress(compressed_data, decompressed_data_size):
    '''
    Decompress input data and return decompressed data as bytes. Based on ms-compress
    https://github.com/coderforlife/ms-compress

    :param compressed_data: Data to decompress
    :param decompressed_data_size: Expected size of decompressed data
    :return: Decompressed data
    '''
    decoder = HuffmanDecoder()
    remaining_data = compressed_data
    code_lengths = []
    [code_lengths.append(0) for _ in range(SYMBOLS)]
    decompressed_data = []
    [decompressed_data.append(0) for _ in range(decompressed_data_size)]

    index = 0
    while True:
        if len(remaining_data) < MIN_DATA:
            if len(remaining_data) != 0:
                raise Exception("Xpress Huffman Decompression Error: Invalid Data: Less than {:d} input bytes".format(
                    MIN_DATA))
            break

        i2 = 0
        for i in range(HALF_SYMBOLS):
            code_lengths[i2] = (remaining_data[i] & 0xF)
            i2 += 1
            code_lengths[i2] = (remaining_data[i] >> 4)
            i2 += 1
        remaining_data = remaining_data[HALF_SYMBOLS:]

        if decoder.set_code_lengths(code_lengths) is False:
            raise Exception("Xpress Huffman Decompression Error: Invalid Data: Unable to resolve Huffman codes")

        # decode data chunk
        bstr = InputBitstream(remaining_data)
        set_remaining = True
        while (index < CHUNK_SIZE) or (bstr.mask_is_zero() is False):
            sym = ct.c_uint32(decoder.decode_symbol(bstr))
            if sym.value == INVALID_SYMBOL:
                raise Exception(
                    "XPRESS Huffman Decompression Error: Invalid data: Unable to read enough bits for symbol")

            if (sym.value == STREAM_END) and (bstr.remaining_raw_bytes() == 0) and (bstr.mask_is_zero() is True):
                set_remaining = False
                remaining_data = bstr.raw_stream()
                break

            if sym.value < 0x100:
                decompressed_data[index] = sym.value
                index += 1
            else:
                length = sym.value & 0xF
                if length == 0xF:
                    if bstr.remaining_raw_bytes() < 1:
                        raise Exception(
                            "XPRESS Huffman Decompression Error: Invalid data: Unable to read extra byte for length")

                    length = bstr.read_raw_byte()
                    if length == 0xFF:
                        if bstr.remaining_raw_bytes() < 2:
                            raise Exception(
                                "XPRESS Huffman Decompression Error: Invalid data: Unable to read two bytes for length")

                        length = bstr.read_raw_uint16()
                        if length == 0:
                            if bstr.remaining_raw_bytes() < 4:
                                raise Exception(
                                    "XPRESS Huffman Decompression Error: Invalid data:\
                                    Unable to read four bytes for length")

                            length = bstr.read_raw_uint32()
                        if length < 0xF:
                            raise Exception(
                                "XPRESS Huffman Decompression Error: Invalid data: Invalid length specified")
                        length -= 0xF
                    length += 0xF
                length += 3

                off_bits = (ct.c_uint32(sym.value).value >> 4) & 0xF

                if off_bits > bstr.available_bits():
                    raise Exception("XPRESS Huffman Decompression Error: Invalid data: \
                    Unable to read {:d} bits for offset".format(sym.value))

                off = bstr.read_bits(off_bits) + (1 << off_bits)

                if list_in_range(decompressed_data, index - off) is False:
                    raise Exception(
                        "XPRESS Huffman Decompression Error: Invalid data: Illegal offset ({:s} {:d}-{:d})".format(
                            decompressed_data, index, off))

                if list_in_range(decompressed_data, index + length - 1) is False:
                    raise Exception("XPRESS Huffman Decompression Error: Insufficient buffer")

                if off == 1:
                    last_byte = decompressed_data[index - 1]
                    for i in range(length):
                        decompressed_data[index] = last_byte
                        index += 1
                else:
                    for i in range(length):
                        decompressed_data[index] = decompressed_data[index - off]
                        index += 1

        if set_remaining:
            remaining_data = bstr.raw_stream()
            if (decoder.decode_symbol(bstr) == STREAM_END) and \
                    (bstr.remaining_raw_bytes() == 0) and \
                    (bstr.mask_is_zero() is True):
                remaining_data = bstr.raw_stream()

        if not remaining_data:
            break

    if len(decompressed_data) != decompressed_data_size:
        raise Exception("Xpress Huffman Decompression Error: Expected decompressed size incorrect")
    return array.array('B', decompressed_data).tostring()


def xpress_decompress(compressed_data, decompressed_data_size):
    try:
        return xpress_huff_decompress(compressed_data, decompressed_data_size)
    except Exception as e:
        print('Could not decompress data {:s}'.format(str(e)))
    return b''


def decompress_data(data):
    '''
    Decompress compressed XPRESS + Huffman data.

    :param data:
    :return:
    '''
    compressed_chunk = data
    total_size = len(compressed_chunk)
    processed_size = 0
    decompressed_chunks = []
    while processed_size < total_size:
        decompressed_chunk_size = get_uint_16(compressed_chunk) + 1
        compressed_chunk_size = get_uint_16(compressed_chunk[2:]) + 1
        decompressed_chunk = xpress_decompress(
            compressed_chunk[4:compressed_chunk_size + 4],
            decompressed_chunk_size)
        decompressed_chunks.append(decompressed_chunk)
        processed_size += compressed_chunk_size + 4
        compressed_chunk = compressed_chunk[compressed_chunk_size + 4:]
    return decompressed_chunks


def decode_data(encoded_data):
    '''
    Decodes base64 data

    :param encoded_data: data to decode
    :return:
    '''
    try:
        return base64.b64decode(encoded_data)
    except binascii.Error as e:
        print('could not base64 decode data Error: {:s}'.format(str(e)))
    return b''


def extract_xml_msges(data):
    '''
    Attempts to extract xml data from data

    :param data: data to attempt to extract xml data from
    :return:
    '''
    tot_string = ''
    cur_string = ''
    num_obj_seen = 0
    start = False
    ret_list = []
    for c in data:
        tot_string += c
        if '<Obj' in tot_string:
            if start is False:
                cur_string = '<Ob'
                start = True
            num_obj_seen += 1
            tot_string = ''

        if '</Obj>' in tot_string:
            num_obj_seen -= 1
            tot_string = ''

        if start is True:
            cur_string += c
            if num_obj_seen == 0:
                ret_list.append(cur_string)
                cur_string = ''
                start = False

    # try to extract single stdout message
    if len(ret_list) == 0:
        tot_string = ''
        cur_string = ''

        for c in data:
            tot_string += c
            if '<S>' in tot_string and start is False:
                cur_string = '<S'
                start = True

            if '</S>' in tot_string:
                cur_string += '>'
                break

            if start is True:
                cur_string += c
        cur_string = cur_string.replace('_x000A_', '\n').replace('&quot;', '\"').replace('_x0009_', '\t')

        if cur_string != '':
            ret_list.append(cur_string)
    return ret_list


def extract_encoded_data(msg):
    '''
    Attempts to extract base64 encoded data from message

    :param msg: message to extract base64 encoded data from
    :return: list of base64 encoded data
    '''
    # enc tags are <rsp:Arguments>, <creationXml>, <rsp:Stream>
    if 'rsp:Arguments' in msg:
        delim = 'rsp:Arguments'
    elif 'creationXml' in msg:
        delim = 'creationXml'
    elif 'rsp:Stream' in msg:
        delim = 'rsp:Stream'
    else:
        return ''
    enc_data = []
    line_data = msg.split(delim)
    for line in line_data:
        if line[0] != '<':
            start = False
            enc_line = ''
            for c in line:
                if c == '>':
                    start = True
                    continue

                if start is True:
                    if c == '<':
                        break
                    enc_line += c

            if enc_line != '':
                enc_data.append(enc_line)
    return enc_data


def build_msg(msg_data):
    '''
    :param msg_data: data to extract msg from
    :return: tuple of flattened message and number of lines it took to build it
    '''
    msg_size = 0
    # remove first line
    msg = '{:s} '.format(msg_data[msg_size].split(' ')[0].strip().strip('\r'))

    # now iterate over remaining message, and flatten it into a single line
    while True:
        msg_size += 1
        msg += ' {:s}'.format(msg_data[msg_size].strip().strip('\r'))
        if msg.endswith('}'):
            msg_size += 1
            break
    return '{:s}\r'.format(msg.replace('\' \'', '')), msg_size


def flatten_msgs(data):
    '''
    Transforms data from human readable input to an easier to parse format
    :param data: input data to transform
    :return: an list of flatten messages
    '''
    msg_data = data.split('\n')
    ret_msgs = []
    msg, size = build_msg(msg_data[0:])
    idx = size
    chunk = msg_data[idx:]
    while len(chunk) > 1:
        ret_msgs.append(msg)
        msg, size = build_msg(chunk)
        idx += size
        chunk = msg_data[idx:]
    return ret_msgs


def parse_msgs(data):
    '''
    Parses input data and returns formatted, decoded, and decompressed data

    :param data: data to be parsed
    :return: Returns parsed winrm message data
    '''
    msg_lines = flatten_msgs(data)
    ret_data = []
    idx = 0
    msg_num = 1
    while idx < len(msg_lines):
        # first split line using , as a delimiter
        cur_line = msg_lines[idx].strip('{').strip('}').split(',')
        soap_msg_present = False
        task_name = ''
        description = ''
        soap_msg = ''
        for i in range(len(cur_line)):
            if 'Task Name' in cur_line[i]:
                task_name = cur_line[i].split(':')[1].strip().strip('\'').strip('\'').strip()

            if 'Description' in cur_line[i]:
                description = cur_line[i].split(':')[1].strip().strip('\'').strip('\'').strip('<').strip('>').strip()

            if 'SoapDocument' in cur_line[i]:
                soap_msg_present = True

        # if soap message is in line then it needs to be decoded and added to soap message buffer
        if soap_msg_present is True:
            # get num of messages
            chunks = 0
            for i in range(len(cur_line)):
                if 'totalChunks' in cur_line[i]:
                    chunks = int(cur_line[i].split(':')[1].strip().strip('}'))

            # parse out additional chunks
            i = 0
            skipped = 0
            while i < chunks:
                # line of SOAP data needs to be parsed differently since it contains encoded data etc.
                cur_soap_line = msg_lines[idx + i + skipped]
                if 'SoapDocument' in cur_soap_line:
                    # parse out SOAP message
                    line_data = ''
                    soap_line_data = ''
                    soap_line_start_count = 0
                    compression_type = ''
                    compression_start = False
                    for c in cur_soap_line:
                        if 'SoapDocument' in line_data:
                            if soap_line_start_count == 5:
                                if soap_line_data.endswith('\', \''):
                                    soap_line_data = soap_line_data[:-4].strip('\n').strip()
                                    break
                                elif soap_line_data.endswith('\''):
                                    soap_line_data = soap_line_data[:-1].strip('\n').strip()
                                    break
                                else:
                                    if '<rsp:CompressionMode>' in soap_line_data and compression_type == '':
                                        compression_start = True

                                    if compression_start is True:
                                        if c == '<':
                                            compression_start = False
                                        else:
                                            compression_type += c
                                    soap_line_data += c
                            else:
                                soap_line_start_count += 1
                        else:
                            line_data += c

                    soap_msg += soap_line_data

                    if compression_type != '':
                        if compression_type != 'XpressCompression':
                            print('WARNING: {:s} compression not supported! Continuing...'.format(
                                compression_type))
                    i += 1

                else:
                    skipped += 1

            idx += (chunks + skipped - 1)
        idx += 1

        encoded_data_list = extract_encoded_data(soap_msg)
        formatted_decoded_data = ''

        if encoded_data_list:
            enc_msg_num = 1
            for encoded_data in encoded_data_list:
                decoded_data = decode_data(encoded_data)

                formatted_decoded_data += 'Decoded Message({:d}) raw:\n\n{!s:s}\n\n'.format(enc_msg_num, decoded_data)
                if type(decoded_data) is bytes and len(decoded_data) > 4:
                    uncompressed_size = get_uint_16(decoded_data) + 1
                    compressed_size = get_uint_16(decoded_data[2:]) + 1
                    if (compressed_size > 0) and (uncompressed_size > 0) and (compressed_size != uncompressed_size):
                        decompressed_data_list = decompress_data(decoded_data)

                        decompressed_data = b''
                        decode = False
                        if not decompressed_data_list:
                            decompressed_data = decoded_data
                        else:
                            for data in decompressed_data_list:
                                if len(decompressed_data_list) > 1:
                                    decode = True
                                decompressed_data += data

                        if decode is True:
                            decoded_data = decode_data(decompressed_data)
                            if decoded_data:
                                decompressed_data = decoded_data
                            else:
                                decode = False

                        formatted_decompressed_data = ''
                        xml_msges = extract_xml_msges(str(decompressed_data))
                        for msg in xml_msges:
                            try:
                                xmlw = xml.dom.minidom.parseString(msg)
                                formatted_decompressed_data += '{:s}\n'.format(xmlw.toprettyxml())
                            except xml.parsers.expat.ExpatError as e:
                                print('could not convert xml Error: {:s}'.format(str(e)))

                        if not formatted_decompressed_data:
                            formatted_decompressed_data = str(decompressed_data)

                        decoded_msg_raw = ''
                        decoded_msg_formatted = ''

                        if decode is True:
                            decoded_msg_raw = '/ Decoded '
                            decoded_msg_formatted = '/ Decoded '

                        formatted_decoded_data += 'Decompressed {:s}Message({:d}) decompressed raw:\n\n{!s:s}\n\n'\
                            .format(decoded_msg_raw,
                                    enc_msg_num,
                                    decompressed_data)
                        formatted_decoded_data += 'Decompressed {:s}Message({:d}) decompressed formatted:\n\n{!s:s}\n'\
                            .format(decoded_msg_formatted,
                                    enc_msg_num,
                                    formatted_decompressed_data)

                    else:
                        decoded_and_formatted_data = ''
                        if decoded_data != '':
                            xml_msges = extract_xml_msges(str(decoded_data))
                            for msg in xml_msges:
                                try:
                                    xmlw = xml.dom.minidom.parseString(msg)
                                    decoded_and_formatted_data += '{:s}\n'.format(xmlw.toprettyxml())
                                except xml.parsers.expat.ExpatError as e:
                                    print('could not convert xml message {:d}, encoded msg {:d} Error: {:s}'.format(
                                        msg_num,
                                        enc_msg_num,
                                          str(e)))
                                    decoded_and_formatted_data += '{!s:s}\n'.format(msg)

                        formatted_decoded_data += 'Decoded Message({:d}) formatted:\n\n{:s}\n'.format(
                            enc_msg_num,
                            decoded_and_formatted_data)
                enc_msg_num += 1
        soap_xml = ''
        if soap_msg != '':
            soap_xml = soap_msg
            try:
                xmlw = xml.dom.minidom.parseString(soap_msg)
                soap_xml = xmlw.toprettyxml()
            except xml.parsers.expat.ExpatError as e:
                print('could not convert xml message {:d} Error: {:s}'.format(msg_num, str(e)))

        msg = 'Message Number: {:d}\nTask Name: {:s}\nDescription: {:s}\nMessage data:\n{:s}\nDecoded data:\n{:s}'\
            .format(msg_num,
                    task_name,
                    description,
                    soap_xml,
                    formatted_decoded_data)
        msg_num += 1
        ret_data.append(msg)

    return '\n'.join(ret_data)


def parse(infile, outfile):
    '''
    Parses input captured WinRM data and writes parsed output to file

    :param infile: file path to read input data from
    :param outfile: file to write output data from
    :return:
    '''
    with open(infile) as in_file:
        out_data = parse_msgs(in_file.read())
        with open(outfile, 'w') as out_file:
            out_file.write(out_data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i',
                        '--infile',
                        help="file to read input from",
                        required=True)
    parser.add_argument('-o',
                        '--outfile',
                        help="file to write output to",
                        required=True)

    args = parser.parse_args()
    parse(args.infile, args.outfile)

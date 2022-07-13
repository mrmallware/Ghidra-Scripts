import argparse
import binascii
import os
import pefile
import struct
import sys


'''
To Do:
    Fix the args stuff

    Add parsing for c2s
        - separate IPs/Ports?
        - Just IPs
        - defang IPs
'''

def string_decode(txt_data):
    strings_list = []
    # idk what these are
    ECS1_string = None
    ECK1_string = None
    
    # look for strings in 1st 0x1000 bytes
    for i in range(0,0x1000,4):
        dword_1 = struct.unpack('<I',txt_data[i:i+4])[0] 
        dword_2 = struct.unpack('<I',txt_data[i+4:i+8])[0]
        # Null the last two bytes, makes sure single byte XOR key
        if (dword_1  & 0xffffff00) ^ (dword_2 & 0xffffff00) == 0:
            # Match
            key = txt_data[i:i+4]
            data_len = dword_1 ^ dword_2
            enc_data = txt_data[i+8:i+8+data_len]
            ptr_data = xor_decrypt(enc_data, key)
            if is_ascii(ptr_data):
                # ignore empty strings
                if ptr_data != b'':
                    # latin 1 to switch between bytes and strings
                    strings_list.append(ptr_data.decode('latin1'))
            if b'ECS1' == ptr_data[:4]:
                ECS1_string = ptr_data
                print('ECS location',hex(i))
            if b'ECK1' == ptr_data[:4]:
                ECK1_string = ptr_data
                print('ECK location',hex(i))
    print(ECS1_string)
    print(ECK1_string)
    for s in strings_list:
        print(s)
    # return ECS1_string, ECK1_string, strings_list

def c2_decode(data_data):
    key = data_data[:4]
    data_len = struct.unpack('<I',data_data[:4])[0] ^ struct.unpack('<I',data_data[4:8])[0]
    enc_data = data_data[8:8+data_len]
    c2 = xor_decrypt(enc_data, key)
    print("\n== C2 List == ")
    for i in range(0,len(c2),8):
        print("%d.%d.%d.%d:%d" % (c2[i+0],c2[i+1],c2[i+2],c2[i+3],struct.unpack('>H',c2[i+4:i+6])[0]))


def is_ascii(s):
    return all(c < 128 for c in s)

def unhex(hex_string):
    if type(hex_string) == str:
        return binascii.unhexlify(hex_string.encode('utf-8'))
    else:
        return binascii.unhexlify(hex_string)

def tohex(data):
    if type(data) == str:
        return binascii.hexlify(data.encode('utf-8'))
    else:
        return binascii.hexlify(data)

def xor_decrypt(data,key):
    out = []
    for i in range(len(data)):
        out.append(data[i] ^ key[i%len(key)])
    return bytes(out)

def main():
    emotet_file = args.file
    data = open(emotet_file, 'rb').read()
    pe = pefile.PE(data = data)

    if args.outfile is not None and os.path.exists(args.outfile):
        print('Output file already exists. Exiting now.')
        sys.exit(1)

    # Make sure text section is inside the PE
    txt_data = None
    for s in pe.sections:
        if b'.text' in s.Name:
            txt_data = s.get_data()
    # Make sure data section is inside the PE
    data_data = None
    for s in pe.sections:
        if b'.data' in s.Name:
            data_data = s.get_data()

    # Make sure txt_data in not empty
    try:
        assert txt_data is not None
    except AssertionError:
        print("There is no text section in this file. Make sure it is a valid PE file.")
        # print("Exiting Now...")
    try:
        assert data_data is not None
    except AssertionError:
        print("There is no data section in this file. Make sure it is a valid PE file.")
        # print("Exiting Now...")
    
    if args.strings:
        strings = string_decode(txt_data)
    elif args.c2:
        c2 = c2_decode(data_data)
    else:
        strings = string_decode(txt_data)
        c2 = c2_decode(data_data)
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract Emotet IOCs.')
    parser.add_argument('-f', '--file', required=True, help='Filepath to emotet exe')
    parser.add_argument('-o', '--outfile', required=False, help='Filepath for output, this file should not already exist on the machine')
    parser.add_argument('-c2', help='Only output c2 list', action = 'store_true')
    parser.add_argument('-s', '--strings', action='store_true', help='Only output decoded embedded strings')

    args = parser.parse_args()
    main()

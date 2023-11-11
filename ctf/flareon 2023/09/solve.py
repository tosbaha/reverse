from unicorn import *
from unicorn.x86_const import *
import os

mu = Uc(UC_ARCH_X86, UC_MODE_16)

if __name__ == "__main__":

    image_path = os.path.join(os.path.dirname(__file__), "rawimage.bin")
    with open(image_path, "rb") as f:
        file_data = f.read()

    hd_serial = bytes([0x34, 0x87, 0xB3, 0xB4, 0x1F, 0x20])

    result = bytearray()
    for i in range(0, len(hd_serial), 2):
        word = (hd_serial[i + 1] << 8) | hd_serial[i]
        word ^= 0x5555
        xor_bytes = bytearray([word & 0xFF, (word >> 8) & 0xFF])
        result.extend(xor_bytes)

    partial_serial = "".join(["{:02X}".format(byte) for byte in result])
    print("Partial Key:", partial_serial)
    byte_serial = b''

    for char in partial_serial:
        byte_value = int(char, 16)
        byte_serial += bytes([byte_value])

    img_base = 0x0600 
    entry_point = 0x11FB

# seg000:11FB                 push    dx
# seg000:11FC                 call    sub_1296 ; check serial
# seg000:11FF                 pop     dx
# seg000:1200                 test    ax, ax

    try:
        # Initialize CPU emulator
        # Write image to the emulator's memory
        mem_size = 0x10000
        mu.mem_map(0, mem_size)
        mu.mem_write(img_base, file_data) # Write MBR
        
        mu.mem_write(0x2A4C,byte_serial) # Partial Key
        mu.mem_write(0x19FC,hd_serial) # HD Serial
        print("Bruteforcing the last 4 chars...")        

        for value in range(65536):
            byte1 = (value >> 12) & 0x0F 
            byte2 = (value >> 8) & 0x0F
            byte3 = (value >> 4) & 0x0F
            byte4 = value & 0x0F
            byte_array = bytes([byte1, byte2, byte3, byte4])

            mu.mem_write(0x2A58, byte_array)
            mu.reg_write(UC_X86_REG_DX, 0x1224)
            # run the serial check routine
            mu.emu_start(entry_point, 0x1200)
            ax_reg = mu.reg_read(UC_X86_REG_AX)
            if (ax_reg == 0): # if ax == 0x18fb serial is wrong.
                # Serial is correct!
                result = byte_serial + byte_array
                hex_string = ''.join(f'{byte:X}' for byte in result)
                print("Full Key: %s" % hex_string)
                exit(0)
        print("Emulation done")
    except UcError as e:
        print("ERROR: %s" % e)
# 61D2E6E14A75
# 61D2E6E14A754ADC
# bl0wf1$h_3ncrypt10n_0f_p@rt1t10n_1n_r3al_m0d3@flare-on.com
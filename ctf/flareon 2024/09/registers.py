# registers.py

from unicorn.x86_const import *

class Register:
    def __init__(self, name, context_offset, unicorn_id):
        self.name = name
        self.context_offset = context_offset
        self.unicorn_id = unicorn_id

    def __repr__(self):
        return f"Register(name='{self.name}', context_offset=0x{self.context_offset:X}, unicorn_id={self.unicorn_id})"

# Define register information with mappings
REGISTER_DATA = [
    ("RAX", 0x78, UC_X86_REG_RAX),
    ("RCX", 0x80, UC_X86_REG_RCX),
    ("RDX", 0x88, UC_X86_REG_RDX),
    ("RBX", 0x90, UC_X86_REG_RBX),
    ("RSP", 0x98, UC_X86_REG_RSP),
    ("RBP", 0xA0, UC_X86_REG_RBP),
    ("RSI", 0xA8, UC_X86_REG_RSI),
    ("RDI", 0xB0, UC_X86_REG_RDI),
    ("R8",  0xB8, UC_X86_REG_R8),
    ("R9",  0xC0, UC_X86_REG_R9),
    ("R10", 0xC8, UC_X86_REG_R10),
    ("R11", 0xD0, UC_X86_REG_R11),
    ("R12", 0xD8, UC_X86_REG_R12),
    ("R13", 0xE0, UC_X86_REG_R13),
    ("R14", 0xE8, UC_X86_REG_R14),
    ("R15", 0xF0, UC_X86_REG_R15),
    ("RIP", 0xF8, UC_X86_REG_RIP),
    ("MxCsr", 0x34, None)  # Unicorn has no MxCsr register ID
]

# Build dictionaries for lookup
registers_by_name = {}
registers_by_context_offset = {}
registers_by_unicorn_id = {}

# Populate dictionaries
for name, context_offset, unicorn_id in REGISTER_DATA:
    reg = Register(name, context_offset, unicorn_id)
    registers_by_name[name] = reg
    registers_by_context_offset[context_offset] = reg
    if unicorn_id is not None:
        registers_by_unicorn_id[unicorn_id] = reg

# Lookup function
def get_register(identifier):
    """
    Retrieve register information by name, context offset, or Unicorn ID.
    :param identifier: Register name (str), context offset (int), or Unicorn ID (int)
    :return: Register object or None if not found
    """
    if isinstance(identifier, str):
        return registers_by_name.get(identifier.upper())
    elif isinstance(identifier, int):
        return registers_by_context_offset.get(identifier) or registers_by_unicorn_id.get(identifier)
    else:
        return None

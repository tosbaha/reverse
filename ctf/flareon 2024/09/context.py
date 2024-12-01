import ctypes

class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", ctypes.c_uint32),
        ("ExceptionFlags", ctypes.c_uint32),
        ("ExceptionRecord", ctypes.c_uint64),
        ("ExceptionAddress", ctypes.c_uint64),
        ("NumberParameters", ctypes.c_uint32),
        ("ExceptionInformation", ctypes.c_uint64 * 15),
    ]

class CONTEXT_CHUNK(ctypes.Structure):
    _fields_ = [
        ("Offset", ctypes.c_int32),
        ("Length", ctypes.c_uint32),
    ]

class CONTEXT_EX(ctypes.Structure):
    _fields_ = [
        ("All", CONTEXT_CHUNK),
        ("Legacy", CONTEXT_CHUNK),
        ("XState", CONTEXT_CHUNK),
    ]

class M128A(ctypes.Structure):
    _fields_ = [
        ("Low", ctypes.c_uint64),
        ("High", ctypes.c_int64)
    ]

class XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_uint16),
        ("StatusWord", ctypes.c_uint16),
        ("TagWord", ctypes.c_uint8),
        ("Reserved1", ctypes.c_uint8),
        ("ErrorOpcode", ctypes.c_uint16),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint16),
        ("Reserved2", ctypes.c_uint16),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint16),
        ("Reserved3", ctypes.c_uint16),
        ("MxCsr", ctypes.c_uint32),
        ("MxCsr_Mask", ctypes.c_uint32),
        ("FloatRegisters", M128A * 8),  # 8 x 128-bit floating point registers
        ("XmmRegisters", M128A * 16),   # 16 x 128-bit SIMD registers
        ("Reserved4", ctypes.c_uint8 * 96)
    ]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        # Control Registers
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),

        # Segment Registers
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),

        # Control Registers
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),

        # Floating Point, Vector and SIMD State
        ("FltSave", XMM_SAVE_AREA32),
        ("VectorRegister", M128A * 26),  # 26 x 128-bit vector registers
        ("VectorControl", ctypes.c_uint64),

        # Debug Control Registers
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]

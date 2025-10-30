// monitor_fixed.js
'use strict';

const moduleName = null;     // null => use main module (first in enumerateModules)
const targetRva2  = 0x2CF1F0; // adjust if needed (RVA from image base)
const targetRva =   0x000432F2E

function getModuleBase(name) {
  const modules = Process.enumerateModules();

  if (!name) {
    if (modules.length === 0) return null;
    return modules[0].base; // main image (first enumerated)
  }
  for (let i = 0; i < modules.length; i++) {
    if (modules[i].name === name) return modules[i].base;
  }
  return null;
}

function hexdumpSafe(ptrAddr, len) {
  try {
    return hexdump(ptrAddr, { length: len, ansi: true });
  } catch (e) {
    return `<hexdump failed: ${e}>`;
  }
}

// === resolve target address ===
let target = null;
let target2 = null;

let base = null;
if (typeof targetAbsolute !== 'undefined') {
  target = targetAbsolute;
} else {
  base = getModuleBase(moduleName);
  if (!base) {
    throw new Error("Unable to find module base. Check moduleName or permissions.");
  }
  target = base.add(ptr(targetRva));
  target2 = base.add(ptr(targetRva2));
}

console.log('[+] monitoring target at: ' + target.toString());
console.log('[+] monitoring base at: ' + base.toString());


// const GetUserNameA = Module.findExportByName('KERNEL32.DLL', 'GetUserNameA');
 //const addr = Module.getExportByName(null, 'GetUserNameA');
const GetUserNameA =  Module.findGlobalExportByName("GetUserNameA");
const GetComputerNameA =  Module.findGlobalExportByName("GetComputerNameA");



const NtSuspendProcess = new NativeFunction(Module.findGlobalExportByName('NtSuspendProcess'), 'uint', ['pointer']);
const GetCurrentProcess = new NativeFunction(Module.findGlobalExportByName('GetCurrentProcess'), 'pointer', []);


const FORCED_TOTAL_BYTES = 6143 * 1024 * 1024; // 6,441,402,368


const time64 =  base.add(0x1470)    //Module.findGlobalExportByName("_time64");
console.log('Time64',time64);


{
  const addr =  Module.findGlobalExportByName('GlobalMemoryStatusEx');
  Interceptor.attach(addr, {
    onEnter(args) {
      this.lp = args[0]; // LPMEMORYSTATUSEX
    },
    onLeave(retval) {
      // MEMORYSTATUSEX layout (x64):
      // +0  DWORD  dwLength
      // +4  DWORD  dwMemoryLoad
      // +8  ULONGLONG ullTotalPhys
      // ...
      
      this.lp.add(8).writeU64(FORCED_TOTAL_BYTES);
    }
  });
}


{
  const addr = Module.findGlobalExportByName('GetSystemInfo');
  Interceptor.attach(addr, {
    onEnter(args) {
      this.lp = args[0]; // LPSYSTEM_INFO
    },
    onLeave(_retval) {
      this.lp.add(32).writeU32(2);
//      Memory.writeU32(this.lp.add(32), 2);
    }
  });

}

const aes = base.add(0x00500C0)


 Interceptor.attach(aes, {
    onEnter(args) {
      // this.arg0 = args[0]
      // this.arg1 = args[1]

      console.log(hexdump(this.context.rcx))
      console.log(hexdump(this.context.rdx))
      console.log(hexdump(this.context.rcx))

    },

     onLeave(retval) {
  }
})



let tragetVal = 1755670327

Interceptor.attach(time64, {
    onEnter(args) {
    },

     onLeave(retval) {
      retval.replace(tragetVal)
  }
})

Interceptor.attach(GetComputerNameA, {
    onEnter(args) {
        this.arg = args[0];
        this.len = args[1]

    },

     onLeave(retval) {
         let username = 'THUNDERNODE'        
        this.len.writeU64((username.length)+1);
        this.arg.writeAnsiString(username);
  }
})

Interceptor.attach(GetUserNameA, {
    onEnter(args) {
        this.arg = args[0];      
        this.len = args[1]

    },

     onLeave(retval) {
        let username = 'TheBoss'  // 'TheBoss'
        this.len.writeU64((username.length)+1);
       this.arg.writeAnsiString(username);
  
  }
})


let counter = 0

Interceptor.attach(target, {
  onEnter(args) {

    this.dstObj = args[0];
    this.srcPtr = args[1];
    this.lenPtr = args[2];
    //console.log(hexdump(this.context.rdi));
    // console.log('    srxc = ', this.context.rdi.readCString());

    counter ++;
    console.log('    src = ', this.srcPtr.readCString());

      //  console.log('onEnter:\n' +
      //     Thread.backtrace(this.context, Backtracer.ACCURATE)
      //     .map(DebugSymbol.fromAddress).join('\n') + '\n');

   
  },
  onLeave(retval) {

  
  }
});

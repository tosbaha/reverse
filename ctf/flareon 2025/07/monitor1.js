// monitor_fixed.js
'use strict';

const moduleName = null;     // null => use main module (first in enumerateModules)
const targetRva  = 0x432E50; // adjust if needed (RVA from image base)
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
let base = null;
if (typeof targetAbsolute !== 'undefined') {
  target = targetAbsolute;
} else {
  base = getModuleBase(moduleName);
  if (!base) {
    throw new Error("Unable to find module base. Check moduleName or permissions.");
  }
  target = base.add(ptr(targetRva));
}

console.log('[+] monitoring target at: ' + target.toString());
console.log('[+] monitoring base at: ' + base.toString());


// const GetUserNameA = Module.findExportByName('KERNEL32.DLL', 'GetUserNameA');
 //const addr = Module.getExportByName(null, 'GetUserNameA');
const GetUserNameA =  Module.findGlobalExportByName("GetUserNameA");
const GetComputerNameA =  Module.findGlobalExportByName("GetComputerNameA");



const NtSuspendProcess = new NativeFunction(Module.findGlobalExportByName('NtSuspendProcess'), 'uint', ['pointer']);
const GetCurrentProcess = new NativeFunction(Module.findGlobalExportByName('GetCurrentProcess'), 'pointer', []);



const time64 =  base.add(0x1470)    //Module.findGlobalExportByName("_time64");
console.log('Time64',time64);

const memcpy =  base.add(0x44D362)

const jsonx = base.add(0xB616C);



Interceptor.attach(jsonx, {
    onEnter(args) {
      this.arg1 =  this.context.rcx;
      this.arg2 =  this.context.rdx;
      this.arg3 =  this.context.rax;

      console.log('jsonx enter')
      console.log(hexdump(this.arg1))
      console.log(hexdump(this.arg2))
      console.log(hexdump(this.arg3))

    },

     onLeave(retval) {
      
  }
})

const sha_shit = base.add(0x000EA8C9 )
const aes_shit = base.add(0x00058A00)

Interceptor.attach(aes_shit, {
    onEnter(args) {
      this.arg1 =  this.context.rcx;
      this.arg2 =  this.context.rdx;
      console.log('AES_Enter')
      console.log(hexdump(this.arg1))
      console.log(hexdump(this.arg2))
    },

     onLeave(retval) {
      console.log('AES_Exit')
      console.log(hexdump(this.arg1))
      console.log(hexdump(this.arg2))
      
  }
})

Interceptor.attach(sha_shit, {
    onEnter(args) {
      this.arg1 =  this.context.rcx;
      this.arg2 =  this.context.rdx;
      console.log('SHA_Enter')
      console.log(hexdump(this.arg1))
      console.log(hexdump(this.arg2))
    },

     onLeave(retval) {
      console.log('SHA_Exit')
      console.log(hexdump(this.arg1))
      console.log(hexdump(this.arg2))
      
  }
})



const getaddrinfo =  Module.findGlobalExportByName("getaddrinfo");

// Interceptor.attach(getaddrinfo, {
//     onEnter(args) {

//       const host = args[0];
//       const hint = args[1];
//       console.log('Addr',hexdump(host))
//       console.log('hint',hexdump(hint))

//     },

//      onLeave(retval) {
      
//   }
// })

// Interceptor.attach(memcpy, {
//     onEnter(args) {

//       const rcx = this.context.rcx;
//       const rdx = this.context.rdx;
//       console.log(hexdump(rcx))
//       console.log(hexdump(rdx))

//     },

//      onLeave(retval) {
      
//   }
// })




Interceptor.attach(time64, {
    onEnter(args) {
    },

     onLeave(retval) {
      const tragetVal = 1755670327
      retval.replace(tragetVal)
      console.log('Retval',retval);
      
  }
})

Interceptor.attach(GetComputerNameA, {
    onEnter(args) {
        this.arg = args[0];
        this.len = args[1]

    },
    //01234
    //THUNDERNODE

     onLeave(retval) {
         let username = 'THUNDERNODE'
        
        // // DESKTOP-M9EP8EQ
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
    counter ++;

    // // Normalize length safely
    // try {
    //   // try toNumber(); fallback to toInt32 if necessary
    //   this.len = (typeof this.lenPtr.toNumber === 'function') ? this.lenPtr.toNumber() : this.lenPtr.toInt32();
    // } catch (e) {
    //   // final fallback
    //   this.len = Number(this.lenPtr);
    // }
    // if (!Number.isFinite(this.len) || this.len < 0) this.len = 0;

   // console.log(hexdumpSafe(this.srcPtr, Math.min(this.len, 256)))

 //  console.log(counter);
  // console.log('    src = ', this.srcPtr.readCString());
   // console.log('onEnter:\n' +
    // Thread.backtrace(this.context, Backtracer.ACCURATE)
    // .map(DebugSymbol.fromAddress).join('\n') + '\n');
    // console.log('Counter',counter);
    if (counter > 0) {
          //console.log('SUSPENDING!!!!!')
          console.log('    src = ', this.srcPtr.readCString());

      }

 //  console.log('    len =', this.lenPtr.toInt32());
  },
  onLeave(retval) {

  
  }
});

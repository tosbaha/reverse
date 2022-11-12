using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;
using Flareon;

internal class Program
{
    private static void Main(string[] args)
    {
        string srcFile = Utils.srcFile();
        string destFile = Utils.destFile();

        // Initialize constants
        FLARE15.flare_74();

        //string result = FLARE15.flared_66(0x06000068);

        // Layer 1 Patches
        Flareon.Patch[] patches = new []
        {
          new Flareon.Patch("flared_66", Flareon.FLARE15.gh_m, Flareon.FLARE15.gh_b),
          new Flareon.Patch("flared_67", Flareon.FLARE15.cl_m, Flareon.FLARE15.cl_b),
          new Flareon.Patch("flared_68", new Dictionary<uint, int>(), Flareon.FLARE15.rt_b),
          new Flareon.Patch("flared_69", Flareon.FLARE15.gs_m, Flareon.FLARE15.gs_b),
          new Flareon.Patch("flared_70", Flareon.FLARE15.wl_m, Flareon.FLARE15.wl_b),
          new Flareon.Patch("flared_35", Flareon.FLARE15.pe_m, Flareon.FLARE15.pe_b),
          new Flareon.Patch("flared_47", Flareon.FLARE15.d_m, Flareon.FLARE15.d_b)
        };

        Console.WriteLine("[+] Patching Layer 1");
        var mod = ModuleDefMD.Load(srcFile);
        File.Copy(srcFile, destFile,true);
        var stream = File.Open(destFile, FileMode.Open);
        var types = mod.GetTypes();
        List<MethodDef> methodDefs = new List<MethodDef>();

        // Get function list
        foreach (var type in types)
        {
            foreach (var fun in type.Methods)
            {
                if (fun.Name.Contains("flare"))
                {
                    methodDefs.Add(fun);
                }
            }
        }



        //byte[] array = FLARE15.flared_69("5aeb2b971");
        //byte[] hashAndReset = FLARE14.h.GetHashAndReset();
        //byte[] array2 = FLARE12.flare_46(hashAndReset, array);



        // Check Layer 2 Ptches

        foreach (var fun in methodDefs)
        {
            int token = (int)fun.MDToken.Raw;
            byte[] arr = FLARE15.flared_70(token);
            if (arr != null)
            {
                Utils.CodePos codepos = Utils.GetOriginalRawILBytes(fun, mod);
                stream.Position = codepos.pos;
                stream.Write(arr, 0, arr.Length);
                Console.WriteLine("Method decrypted! {0}", fun.Name);
            }
            else
            {
                Console.WriteLine("Method NOT supprted {0}", fun.Name);
            }
        }

        //foreach(var fun in methodDefs)

        //{
        //    Utils.testme(fun, mod);
        //}

        // Layer 1 Patch
        foreach (Flareon.Patch patch in patches)
        {
            var fun = methodDefs.Find(x => x.Name == patch.name);
            if (fun != null)
            {
                Console.WriteLine("Token : 0x{0:X}", fun.MDToken.Raw);
                Console.WriteLine(" [x] Patching {0}", patch.name);
                Utils.CodePos codepos = Utils.GetOriginalRawILBytes(fun, mod);
                byte[] patched = Utils.PatchLayer1(patch.dict, patch.bytes);
                stream.Position = codepos.pos;
                stream.Write(patched, 0, patched.Length);
            } else {
                Console.WriteLine(" [x] Can't find patch! {0}", patch.name);
            }
        }

        // Layer 2 Patch

        stream.Close();
        Console.WriteLine("[+] Finished!");
    }
}
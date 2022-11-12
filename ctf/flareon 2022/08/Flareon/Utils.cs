using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.PE;
using Flareon;

   public class Utils
    {


    public static string srcFile()
    {
        string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        return Path.Combine(path, "FlareOn.Backdoor.exe");
    }

    public static string destFile()
    {
        return srcFile().Replace("FlareOn.Backdoor.exe", "FlareOn.Backdoor_patched.exe");
    }

    public static byte[] PatchLayer1(Dictionary<uint,int> dict,byte[ ]patches)
    {
        foreach ( (var key, var value) in dict) {
            patches[(int)key] = (byte)value;
            patches[(int)key+1] = (byte)(value >> 8);
            patches[(int)key+2] = (byte)(value >> 16); ;
            patches[(int)key+3] = (byte)(value >> 24); ;
        }
        return patches;
    }

    public struct CodePos
    {
        public uint pos;
        public byte[] bytes;
        public CodePos(uint pos, byte[] bytes)
        {
            this.pos = pos;
            this.bytes = bytes;
        }
    }

    public static void testme(MethodDef methodDef, ModuleDefMD module)
    {


        byte[] bytes = Encoding.ASCII.GetBytes(methodDef.Attributes.ToString());
        byte[] bytes2 = Encoding.ASCII.GetBytes(methodDef.ReturnType.ToString());
        byte[] bytes3 = Encoding.ASCII.GetBytes(methodDef.CallingConvention.ToString());
        byte[] bytes4 = Encoding.ASCII.GetBytes(methodDef.Body.MaxStack.ToString());
        //text =             foreach (LocalVariableInfo localVariableInfo in methodBody.LocalVariables)

        //    byte[] bytes6 = Encoding.ASCII.GetBytes(text);
        //text2 =             foreach (ParameterInfo parameterInfo in methodInfo.GetParameters())

        //    byte[] bytes7 = Encoding.ASCII.GetBytes(text2);


        var reader = module.Metadata.PEImage.CreateReader(methodDef.RVA);
        byte b = reader.ReadByte();
        uint codeSize = 0;
        switch (b & 7)
        {
            case 2:
            case 6:
                codeSize = (uint)(b >> 2);
                break;
            case 3:
                ushort header = (ushort)(reader.ReadByte() << 8 | b);
                int headerSize = (header >> 12) * sizeof(uint);
                reader.ReadUInt16();
                codeSize = reader.ReadUInt32();
                reader.Position = (uint)headerSize;
                break;
        }

        // read actual body
        var pos = reader.CurrentOffset;
        byte[] ilBytes = new byte[codeSize];
        reader.ReadBytes(ilBytes, 0, ilBytes.Length);
        byte[] bytes5 = BitConverter.GetBytes(codeSize);

        Console.WriteLine("Bytes 1 {0}", Convert.ToHexString(bytes));
        Console.WriteLine("Bytes 2 {0}", Convert.ToHexString(bytes2));
        Console.WriteLine("Bytes 3 {0}", Convert.ToHexString(bytes3));
        Console.WriteLine("Bytes 4 {0}", Convert.ToHexString(bytes4));
        Console.WriteLine("Bytes 5 {0}", Convert.ToHexString(bytes5));
        //Console.WriteLine("Bytes 6 {0}", Convert.ToHexString(bytes6));
        //Console.WriteLine("Bytes 7 {0}", Convert.ToHexString(bytes7));




    }

    public static CodePos GetOriginalRawILBytes(MethodDef methodDef, ModuleDefMD module)
    {
        var reader = module.Metadata.PEImage.CreateReader(methodDef.RVA);        
        byte b = reader.ReadByte();

        // parse header info and determine code size
        uint codeSize = 0;
        switch (b & 7)
        {
            case 2:
            case 6:
                codeSize = (uint)(b >> 2);
                break;
            case 3:
                ushort header = (ushort)(reader.ReadByte() << 8 | b);
                int headerSize = (header >> 12) * sizeof(uint);
                reader.ReadUInt16();
                codeSize = reader.ReadUInt32();
                reader.Position = (uint)headerSize;
                break;
        }

        // read actual body
        var pos = reader.CurrentOffset;
        byte[] ilBytes = new byte[codeSize];
        reader.ReadBytes(ilBytes, 0, ilBytes.Length);
        return new CodePos(pos,ilBytes);
    }

    public Utils()
        {

        }
    }
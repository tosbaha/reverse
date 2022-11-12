using System;
namespace Flareon
{
    public struct Patch
    {
        public string name;
        public Dictionary<uint, int> dict;
        public byte[] bytes;

        public Patch(string name, Dictionary<uint, int> dict, byte[] bytes)
        {
            this.name = name;
            this.dict = dict;
            this.bytes = bytes;
        }
    }

}


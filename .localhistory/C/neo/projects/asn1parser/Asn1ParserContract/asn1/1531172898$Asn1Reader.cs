using Neo.SmartContract.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1
{
    public class Asn1Reader
    {
        public Map<byte, bool> excludedTags;
        public Map<Int64, AsnInternalMap> offsetMap;
        public Map<byte, bool> multiNestedTypes;
        public Map<byte, bool> tmpHTable;

        public AsnInternalMap currentPosition;
        public Int32 childCount;
        public bool isTaggedConstructed;
        public Int32 Offset;
        public Byte Tag;
        public String TagName;
        public int TagLength;
        public int PayloadStartOffset;
        public int PayloadLength;
        public int NextCurrentLevelOffset;
        public int NextOffset;
        public bool IsConstructed;
        public byte[] RawData;
    }
}

using Neo.SmartContract.Framework.Services.Neo;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1.utils
{
    public class Asn1Logger
    {
        public static void LogCurrentNodeValues(Asn1Data asn1Reader, string nodeType)
        {
            byte[] headerBytes = Asn1Parser.GetHeader(asn1Reader);
            byte[] payloadBytes = Asn1Parser.GetPayload(asn1Reader);
            byte[] tagRawDataBytes = Asn1Parser.GetTagRawData(asn1Reader);
            int nestedNodeCount = Asn1Parser.GetNestedNodeCount(asn1Reader);

            Storage.Put(Storage.CurrentContext, "NodeType", nodeType);
            Storage.Put(Storage.CurrentContext, "Header", headerBytes);
            Storage.Put(Storage.CurrentContext, "Payload", payloadBytes);
            Storage.Put(Storage.CurrentContext, "TagRawData", tagRawDataBytes);
            Storage.Put(Storage.CurrentContext, "NestedNodeCount", nestedNodeCount);
        }
    }
}

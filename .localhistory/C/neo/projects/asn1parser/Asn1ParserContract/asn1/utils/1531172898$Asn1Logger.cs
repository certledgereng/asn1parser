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
        public static void LogCurrentNodeValues(Asn1Reader asn1Reader, string nodeType)
        {
            byte[] headerBytes = Asn1ReaderT.GetHeader(asn1Reader);
            byte[] payloadBytes = Asn1ReaderT.GetPayload(asn1Reader);
            byte[] tagRawDataBytes = Asn1ReaderT.GetTagRawData(asn1Reader);
            int nestedNodeCount = Asn1ReaderT.GetNestedNodeCount(asn1Reader);

            Storage.Put(Storage.CurrentContext, "NodeType", nodeType);
            Storage.Put(Storage.CurrentContext, "Header", headerBytes);
            Storage.Put(Storage.CurrentContext, "Payload", payloadBytes);
            Storage.Put(Storage.CurrentContext, "TagRawData", tagRawDataBytes);
            Storage.Put(Storage.CurrentContext, "NestedNodeCount", nestedNodeCount);
        }
    }
}

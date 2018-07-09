using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1.time
{
    public class Asn1UtcTimeParser
    {
        public static byt[] Decode(byte[] rawData)
        {
            Asn1Data asn1Data = Asn1Parser.ParseFromRawData(rawData);
            return Asn1Parser.GetPayload(asn1Data);
        }
    }
}

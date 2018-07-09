using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1.time
{
    public class Asn1UtcTimeParser
    {
        public static byte[] Decode(Asn1Data asn1Data)
        {
            //todo: convert byte string to ulong date
            return Asn1Parser.GetPayload(asn1Data);
        }
    }
}

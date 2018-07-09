using Asn1ParserContract.asn1.time;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1
{
    public class Asn1Utils
    {
        public static byte[] DecodeDateTime(Asn1Data asn1Data)
        {
            switch (asn1Data.Tag)
            {
                case (Byte)Asn1Type.UTCTime:
                    return Asn1UtcTimeParser.Decode(asn1Data);
                case (Byte)Asn1Type.Generalizedtime:
                    return Asn1GeneralizedTimeParser.Decode(asn1Data);
                default:
                    {
                        //todo: Handle exceptions
                        return null;
                    }
            }
        }
    }
}

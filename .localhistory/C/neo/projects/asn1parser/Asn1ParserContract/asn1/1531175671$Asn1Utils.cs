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
        public static byte[] DecodeDateTime(Byte[] rawData)
        {
            Asn1Data asn1Data = Asn1Parser.ParseFromRawData(rawData);
            switch (asn1Data.Tag)
            {
                case (Byte)Asn1Type.UTCTime:
                    return Asn1UtcTimeParser.Decode(rawData);
                case (Byte)Asn1Type.Generalizedtime:
                    return Asn1GeneralizedTimeParser.Decode(rawData);
                default:
                    {
                        //todo: Handle exceptions
                        return null;
                    }
            }
        }
    }
}

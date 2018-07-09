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
        public static long DecodeDateTime(Byte[] rawData)
        {
            Asn1Data asn1Data = Asn1Parser.ParseFromRawData(rawData);
            switch (asn1Data.Tag)
            {
                case (Byte)Asn1Type.UTCTime: return Asn1UtcTimeParser.Decode(rawData);
                case (Byte)Asn1Type.Generalizedtime: return DecodeGeneralizedTime(rawData);
                default:
                    {
                        return -1;
                    }
            }
        }
        public static long DecodeUTCTime(Byte[] rawData)
        {
            if (rawData == null) {
                Logger.writeLog("ERROR-raw data is null");
                return -1;
            }
            Asn1Data asn1Data = Asn1Parser.ParseFromRawData(rawData);
           
            return (new Asn1UtcTime(asn)).Value;
        }

        static String DecodeUtcTime(Asn1Data asn1Data)
        {
            DateTime dt = Asn1UtcTime.Decode(asn);
            return dt.ToShortDateString() + " " + dt.ToShortTimeString();
        }
        static String DecodeGeneralizedTime(Asn1Reader asn)
        {
            DateTime dt = Asn1GeneralizedTime.Decode(asn);
            return dt.ToShortDateString() + " " + dt.ToShortTimeString();
        }
    }
}

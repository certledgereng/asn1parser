using Asn1ParserContract.asn1;
using Asn1ParserContract.asn1.utils;
using Neo.SmartContract.Framework;

namespace Asn1ParserContract
{
    public class Asn1ParserSmartContract : SmartContract
    {
        public static void Main()
        {
            byte[] dataBytes = new byte[] { 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x32, 0x30, 0x34, 0x32, 0x37, 0x31, 0x30, 0x33, 0x31, 0x31, 0x38, 0x5A, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x34, 0x32, 0x35, 0x31, 0x30, 0x33, 0x31, 0x31, 0x38, 0x5A };
            Asn1Data asn1Data = Asn1Parser.ParseFromRawData(dataBytes);
            Asn1Logger.LogCurrentNodeValues(asn1Data, "Validity");

            bool isMovedNext = Asn1Parser.MoveNext(asn1Data);
            if (isMovedNext)
            {
                Asn1Logger.LogCurrentNodeValues(asn1Data, "StartDate");
                isMovedNext = Asn1Parser.MoveNext(asn1Data);
                if (isMovedNext)
                {
                    Asn1Logger.LogCurrentNodeValues(asn1Data, "EndDate");
                }
                else
                {
                    Logger.writeLog("ERROR-Can not move to EndDate");
                }
            }
            else
            {
                Logger.writeLog("ERROR-Can not move to StartDate");
            }
        }
    }
}

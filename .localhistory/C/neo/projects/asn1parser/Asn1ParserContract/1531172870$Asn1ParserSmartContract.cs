using Asn1ParserContract.asn1;
using Asn1ParserContract.asn1.utils;
using Neo.SmartContract.Framework;

namespace Asn1ParserContract
{
    public class Asn1ParserSmartContract : SmartContract
    {
        public static void Main()
        {
            Logger.writeLog("Starting Smart Contract Main -->");
            byte[] dataBytes = new byte[] { 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x32, 0x30, 0x34, 0x32, 0x37, 0x31, 0x30, 0x33, 0x31, 0x31, 0x38, 0x5A, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x34, 0x32, 0x35, 0x31, 0x30, 0x33, 0x31, 0x31, 0x38, 0x5A };
            Logger.writeLog("Constructing asn1Reader class");
            Asn1Reader asn1Reader = Asn1ReaderT.FromRawData(dataBytes);
            Logger.writeLog("Constructed asn1Reader class");
            Asn1Logger.LogCurrentNodeValues(asn1Reader, "Validity");

            bool isMovedNext = Asn1ReaderT.MoveNext(asn1Reader);
            if (isMovedNext)
            {
                Logger.writeLog("Moved to StartDate");
                Asn1Logger.LogCurrentNodeValues(asn1Reader, "StartDate");
                isMovedNext = Asn1ReaderT.MoveNext(asn1Reader);
                if (isMovedNext)
                {
                    Logger.writeLog("Moved to EndDate");
                    Asn1Logger.LogCurrentNodeValues(asn1Reader, "EndDate");
                }
                else
                {
                    Logger.writeLog("Can not move to EndDate");
                }
            }
            else
            {
                Logger.writeLog("Can not move to StartDate");
            }
        }
    }
}

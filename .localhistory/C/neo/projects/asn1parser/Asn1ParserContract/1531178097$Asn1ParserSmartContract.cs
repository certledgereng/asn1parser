using Asn1ParserContract.asn1;
using Asn1ParserContract.asn1.utils;
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;

namespace Asn1ParserContract
{
    public class Asn1ParserSmartContract : SmartContract
    {
        public static void Main()
        {
            byte[] validityDataBytes = new byte[] { 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x32, 0x30, 0x34, 0x32, 0x37, 0x31, 0x30, 0x33, 0x31, 0x31, 0x38, 0x5A, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x34, 0x32, 0x35, 0x31, 0x30, 0x33, 0x31, 0x31, 0x38, 0x5A };
            Storage.Put(Storage.CurrentContext, "Validity Data Encoded", validityDataBytes);

            Asn1Data asn1Data = Asn1Parser.ParseFromRawData(validityDataBytes);

            bool isMovedNext = Asn1Parser.MoveNext(asn1Data);
            if (isMovedNext)
            {
                byte[] notBeforeByte = Asn1Utils.DecodeDateTime(asn1Data);
                Storage.Put(Storage.CurrentContext, "notBefore", notBeforeByte);
                isMovedNext = Asn1Parser.MoveNext(asn1Data);
                if (isMovedNext)
                {
                  byte [] notAfterByte = Asn1Utils.DecodeDateTime(asn1Data);
                    Storage.Put(Storage.CurrentContext, "notAfter", notBeforeByte);
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

using Asn1ParserContract.asn1.utils;
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1
{
    public class Asn1Parser
    {
        public static Asn1Data ParseFromRawData(byte[] rawData)
        {
            Asn1Data asn1Data = FromRawData(rawData, 0);
            return asn1Data;
        }
        public static Asn1Data FromRawData(Byte[] rawData, Int32 offset)
        {
            if (rawData == null)
            {
                Logger.writeLog("ERROR-rawData is null");
                return null;
            }
            if (rawData.Length < 2)
            {
                Logger.writeLog("ERROR-rawData.Length must be upper than 2");
                return null;
            }
            Asn1Data asn1Data = new Asn1Data();
            InitMemberDefaultValues(asn1Data);
            Initialize(asn1Data, rawData, offset);
            return asn1Data;
        }

        static void InitMemberDefaultValues(Asn1Data asn1Data)
        {
            asn1Data.excludedTags = new Map<byte, bool>();
            asn1Data.offsetMap = new Map<Int64, AsnInternalMap>();
            asn1Data.multiNestedTypes = new Map<byte, bool>();
            asn1Data.tmpHTable = new Map<byte, bool>();

            asn1Data.excludedTags[0] = true;
            asn1Data.excludedTags[1] = true;
            asn1Data.excludedTags[2] = true;
            asn1Data.excludedTags[5] = true;
            asn1Data.excludedTags[6] = true;
            asn1Data.excludedTags[9] = true;
            asn1Data.excludedTags[10] = true;
            asn1Data.excludedTags[13] = true;

            asn1Data.multiNestedTypes[(Byte)Asn1Type.SEQUENCE] = true;
            asn1Data.multiNestedTypes[(Byte)((Byte)Asn1Type.SEQUENCE | (Byte)Asn1Class.CONSTRUCTED)] = true;
            asn1Data.multiNestedTypes[(Byte)Asn1Type.SET] = true;
            asn1Data.multiNestedTypes[(Byte)((Byte)Asn1Type.SET | (Byte)Asn1Class.CONSTRUCTED)] = true;
            asn1Data.currentPosition = new AsnInternalMap();

            asn1Data.offsetMap[0] = asn1Data.currentPosition;
        }

        public static void Initialize(Asn1Data asn1Data, Byte[] raw, Int32 pOffset)
        {
            asn1Data.IsConstructed = false;
            if (raw != null)
            {
                asn1Data.RawData = raw;
            }
            asn1Data.Offset = pOffset;
            asn1Data.Tag = asn1Data.RawData[asn1Data.Offset];
            CalculateLength(asn1Data);
            // strip possible unnecessary bytes
            if (raw != null && asn1Data.TagLength != asn1Data.RawData.Length)
            {
                asn1Data.RawData = raw.Take(asn1Data.TagLength);
            }
            GetTagName(asn1Data, asn1Data.Tag);
            // 0 Tag is reserved for BER and is not available in DER
            if (asn1Data.Tag == 0)
            {
                Logger.writeLog("ERROR-Invalid tag");
                return;
                //throw new Asn1InvalidTagException(asn1Data.Offset);
            }
            if (asn1Data.PayloadLength == 0)
            {
                int rawDataLength = asn1Data.RawData.Length;
                int offsetAndTagLength = asn1Data.Offset + asn1Data.TagLength;
                if (offsetAndTagLength == rawDataLength)
                {
                    asn1Data.NextOffset = 0;
                }
                else
                {
                    asn1Data.NextOffset = offsetAndTagLength;
                }

                // TODO check this
                if (asn1Data.currentPosition.LevelEnd == 0 ||
                    asn1Data.Offset - asn1Data.currentPosition.LevelStart + asn1Data.TagLength == asn1Data.currentPosition.LevelEnd)
                {
                    asn1Data.NextCurrentLevelOffset = 0;
                }
                else
                {
                    asn1Data.NextCurrentLevelOffset = asn1Data.NextOffset;
                }
                //NextCurrentLevelOffset = NextOffset;
                return;
            }

            ParseNestedType(asn1Data);
            if (asn1Data.Offset - asn1Data.currentPosition.LevelStart + asn1Data.TagLength < asn1Data.currentPosition.LevelEnd)
            {
                asn1Data.NextCurrentLevelOffset = asn1Data.Offset + asn1Data.TagLength;
            }
            else
            {
                asn1Data.NextCurrentLevelOffset = 0;
            }

            if (asn1Data.IsConstructed)
            {
                if (asn1Data.Tag == 3)
                {
                    asn1Data.NextOffset = asn1Data.PayloadStartOffset + 1;
                }
                else
                {
                    asn1Data.NextOffset = asn1Data.PayloadStartOffset;
                }
            }
            else
            {
                if (asn1Data.Offset + asn1Data.TagLength < asn1Data.RawData.Length)
                {
                    asn1Data.NextOffset = asn1Data.Offset + asn1Data.TagLength;
                }
                else
                {
                    asn1Data.NextOffset = 0;
                }
            }
        }
        static void CalculateLength(Asn1Data asn1Data)
        {
            if (asn1Data.RawData[asn1Data.Offset + 1] < 128)
            {
                asn1Data.PayloadStartOffset = asn1Data.Offset + 2;
                asn1Data.PayloadLength = asn1Data.RawData[asn1Data.Offset + 1];
                asn1Data.TagLength = asn1Data.PayloadLength + 2;
            }
            else
            {
                Int32 lengthbytes = asn1Data.RawData[asn1Data.Offset + 1] - 128;
                // max length can be encoded by using 4 bytes.
                if (lengthbytes > 4)
                {
                    Logger.writeLog("ERROR-Data length is too large.");
                }
                asn1Data.PayloadStartOffset = asn1Data.Offset + 2 + lengthbytes;
                asn1Data.PayloadLength = asn1Data.RawData[asn1Data.Offset + 2];
                for (Int32 i = asn1Data.Offset + 3; i < asn1Data.PayloadStartOffset; i++)
                {
                    asn1Data.PayloadLength = (asn1Data.PayloadLength << 8) | asn1Data.RawData[i];
                }
                asn1Data.TagLength = asn1Data.PayloadLength + lengthbytes + 2;
            }
        }
        static void GetTagName(Asn1Data asn1Data, Byte tag)
        {
            asn1Data.TagName = "undefined";
            /*
            Asn1Type type = ((Asn1Type)(tag & 31));
             if ((tag & (Byte)Asn1Class.PRIVATE) != 0) {
                 switch (tag & (Byte)Asn1Class.PRIVATE) {
                     case (Byte)Asn1Class.CONTEXT_SPECIFIC:
                         asn1Data.TagName = "CONTEXT SPECIFIC (" + (tag & 31) + ")";
                         asn1Data.isTaggedConstructed = (tag & (Byte)Asn1Class.CONSTRUCTED) > 0;
                         break;
                     case (Byte)Asn1Class.APPLICATION:
                         asn1Data.TagName = "APPLICATION (" + (tag & 31) + ")";
                         break;
                     case (Byte)Asn1Class.PRIVATE:
                         asn1Data.TagName = "PRIVATE (" + (tag & 31) + ")";
                         break;
                     case (Byte)Asn1Class.CONSTRUCTED:
                         asn1Data.TagName = "CONSTRUCTED (" + (tag & 31) + ")";
                         break;
            }
         } else {
                 asn1Data.TagName = ((Asn1Type)(tag & 31))+"";
             }*/
        }
        static void ParseNestedType(Asn1Data asn1Data)
        {
            // processing rules (assuming zero-based bits):
            // if bit 5 is set to "1", or the type is SEQUENCE/SET -- the type is constructed. Unroll nested types.
            // if bit 5 is set to "0", attempt to resolve nested types only for UNIVERSAL tags.
            if (asn1Data.excludedTags.HasKey(asn1Data.Tag) || asn1Data.PayloadLength < 2)
            {
                return;
            }
            Int64 pstart = asn1Data.PayloadStartOffset;
            Int32 plength = asn1Data.PayloadLength;

            if (asn1Data.Tag == 3)
            {
                pstart = asn1Data.PayloadStartOffset + 1;
                plength = asn1Data.PayloadLength - 1;
            }

            if (asn1Data.multiNestedTypes.HasKey(asn1Data.Tag) ||
                (asn1Data.Tag & (Byte)Asn1Class.CONSTRUCTED) > 0)
            {
                asn1Data.IsConstructed = true;
                if (!asn1Data.offsetMap.HasKey(pstart))
                {
                    PredictResult predictResult = Predict(asn1Data, pstart, plength, true);
                    asn1Data.childCount = predictResult.estimatedChildCount;
                }
                asn1Data.isTaggedConstructed = false;
                return;
            }
            if (asn1Data.Tag > 0 && asn1Data.Tag < (Byte)Asn1Type.TAG_MASK)
            {
                PredictResult predictResult = Predict(asn1Data, pstart, plength, false);
                asn1Data.childCount = predictResult.estimatedChildCount;
                asn1Data.IsConstructed = predictResult.result;
                // reiterate again and build map for children
                if (asn1Data.IsConstructed && !asn1Data.offsetMap.HasKey(pstart))
                {
                    PredictResult predictResultOther = Predict(asn1Data, pstart, plength, false);
                    asn1Data.childCount = predictResultOther.estimatedChildCount;
                }
            }
            asn1Data.isTaggedConstructed = false;
        }
        public class PredictResult
        {
            public Boolean result;
            public Int32 estimatedChildCount;
        }
        static PredictResult Predict(Asn1Data asn1Data, Int64 start, Int32 projectedLength, bool assignMap)
        {
            Int64 levelStart = start;
            Int64 sum = 0;
            PredictResult predictResult = new PredictResult();
            predictResult.estimatedChildCount = 0;
            do
            {
                if (start < 0 || start >= asn1Data.RawData.Length || asn1Data.RawData[start] == 0)
                {
                    predictResult.result = false;
                    return predictResult;
                }
                Int64 pl = CalculatePredictLength(asn1Data, start);
                sum += pl;
                if (assignMap && sum <= projectedLength)
                {
                    asn1Data.offsetMap[start] = new AsnInternalMap { LevelStart = levelStart, LevelEnd = projectedLength };
                }
                start += pl;
                predictResult.estimatedChildCount++;
            } while (sum < projectedLength);
            if (sum != projectedLength)
            {
                predictResult.estimatedChildCount = 0;
            }
            predictResult.result = sum == projectedLength;
            return predictResult;
        }
        static Int64 CalculatePredictLength(Asn1Data asn1Data, Int64 offset)
        {
            if (offset + 1 >= asn1Data.RawData.Length || offset < 0)
            {
                return Int32.MaxValue;
            }
            if (asn1Data.RawData[offset + 1] < 128)
            {
                return asn1Data.RawData[offset + 1] + 2;
            }
            Int32 lengthbytes = asn1Data.RawData[offset + 1] - 128;
            // max length can be encoded by using 4 bytes.
            if (lengthbytes > 4)
            {
                return Int32.MaxValue;
            }
            Int32 ppayloadLength = asn1Data.RawData[offset + 2];
            for (Int64 i = offset + 3; i < offset + 2 + lengthbytes; i++)
            {
                ppayloadLength = (ppayloadLength << 8) | asn1Data.RawData[i];
            }
            // 2 -- transitional + tag
            return ppayloadLength + lengthbytes + 2;
        }
        static Boolean MoveAndExpectTypesWithMoveNextCurrentLevel(Asn1Data asn1Data, params Byte[] expectedTypes)
        {
            if (expectedTypes == null) { return false; }

            foreach (Byte tag in expectedTypes)
            {
                asn1Data.tmpHTable[tag] = true;
            }
            if (!MoveNextCurrentLevel(asn1Data)) { return false; }

            if (!asn1Data.tmpHTable.HasKey(asn1Data.Tag))
            {
                Logger.writeLog("ERROR-Tag Not Found");
                return false;
                //throw new Asn1InvalidTagException();
            }
            return true;
        }
        static void MoveAndExpectTypesWithMoveNext(Asn1Data asn1Data, params Byte[] expectedTypes)
        {
            if (expectedTypes == null) { throw new ArgumentNullException(nameof(expectedTypes)); }
            foreach (Byte tag in expectedTypes)
            {
                asn1Data.tmpHTable[tag] = true;
            }
            if (!MoveNext(asn1Data))
            {
                Logger.writeLog("ERROR-Data is invalid");
                return;
            }

            if (!asn1Data.tmpHTable.HasKey(asn1Data.Tag))
            {
                Logger.writeLog("ERROR-Invalid Tag");
            }
        }
        public static Byte[] GetHeader(Asn1Data asn1Data)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Data.RawData, asn1Data.Offset, asn1Data.PayloadStartOffset - asn1Data.Offset);
        }
        public static Byte[] GetPayload(Asn1Data asn1Data)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Data.RawData, asn1Data.PayloadStartOffset, asn1Data.PayloadLength);
        }
        public static Byte[] GetTagRawData(Asn1Data asn1Data)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Data.RawData, asn1Data.Offset, asn1Data.TagLength);
        }
        public static Int32 GetNestedNodeCount(Asn1Data asn1Data)
        {
            return asn1Data.IsConstructed ? asn1Data.childCount : 0;
        }
        public static Boolean MoveNext(Asn1Data asn1Data)
        {
            if (asn1Data.NextOffset == 0)
            {
                return false;
            }
            //projectedIterationSize = _offsetMap[NextOffset];
            asn1Data.currentPosition = asn1Data.offsetMap[asn1Data.NextOffset];
            Initialize(asn1Data, null, asn1Data.NextOffset);
            return true;
        }
        public static void MoveNextAndExpectTags(Asn1Data asn1Data, params Byte[] expectedTags)
        {
            MoveAndExpectTypesWithMoveNext(asn1Data, expectedTags);
        }
        public static Boolean MoveNextCurrentLevel(Asn1Data asn1Data)
        {
            if (asn1Data.NextCurrentLevelOffset == 0) { return false; }
            asn1Data.currentPosition = asn1Data.offsetMap[asn1Data.NextCurrentLevelOffset];
            Initialize(asn1Data, null, asn1Data.NextCurrentLevelOffset);
            return true;
        }
        public static void MoveNextCurrentLevelAndExpectTags(Asn1Data asn1Data, params Byte[] expectedTags)
        {
            MoveAndExpectTypesWithMoveNextCurrentLevel(asn1Data, expectedTags);
        }
        public static Boolean MoveToPoisition(Asn1Data asn1Data, Int32 newPosition)
        {
            if (asn1Data.offsetMap == null)
            {
                throw new InvalidOperationException();
            }
            if (asn1Data.offsetMap[newPosition] == null)
            {
                return false;
            }
            asn1Data.currentPosition = asn1Data.offsetMap[newPosition];
            Initialize(asn1Data, null, newPosition);
            return true;
        }
        public static void Reset(Asn1Data asn1Data)
        {
            asn1Data.currentPosition = asn1Data.offsetMap[0];
            Initialize(asn1Data, null, 0);
        }
        public static Int32 BuildOffsetMap(Asn1Data asn1Data)
        {
            Reset(asn1Data);
            do { } while (MoveNext(asn1Data));
            Reset(asn1Data);
            return 1;//asn1Data._offsetMap.Keys.Size();
        }
    }
}

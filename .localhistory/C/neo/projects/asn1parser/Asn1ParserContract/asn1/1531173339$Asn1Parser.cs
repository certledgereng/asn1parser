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
            Logger.writeLog("(Start)FromRawData - Byte[]");
            Asn1Data asn1Data = FromRawData(rawData, 0);
            Logger.writeLog("(End)FromRawData - Byte[]");
            return asn1Data;
        }
        public static Asn1Data FromRawData(Byte[] rawData, Int32 offset)
        {
            Logger.writeLog("(Start)FromRawData - Byte[],Int32");
            if (rawData == null)
            {
                Logger.writeLog("rawData is null");
                // throw new ArgumentNullException("rawData");
            }
            if (rawData.Length < 2)
            {
                Logger.writeLog("ERROR-rawData.Length must be upper than 2");
                //throw new Win32Exception("Invalid Data");
            }

            Logger.writeLog("Constructing asn1Data object");
            Asn1Data asn1Data = new Asn1Data();
            Logger.writeLog("Constructed asn1Data object");
            InitMemberDefaultValues(asn1Data);

            Logger.writeLog("Calling Initialize with asn1Data,rawData and offset");
            Initialize(asn1Data, rawData, offset);
            Logger.writeLog("Called Initialize with asn1Data,rawData and offset");
            Logger.writeLog("(End)FromRawData - Byte[],Int32");
            return asn1Data;
        }

        static void InitMemberDefaultValues(Asn1Data asn1Data)
        {
            Logger.writeLog("(Start)initMembers");
            asn1Data.excludedTags = new Map<byte, bool>();
            asn1Data.offsetMap = new Map<Int64, AsnInternalMap>();
            asn1Data.multiNestedTypes = new Map<byte, bool>();
            asn1Data.tmpHTable = new Map<byte, bool>();
            Logger.writeLog("(End)initMembers");

            Logger.writeLog("Initializing _excludedTags map");
            asn1Data.excludedTags[0] = true;
            asn1Data.excludedTags[1] = true;
            asn1Data.excludedTags[2] = true;
            asn1Data.excludedTags[5] = true;
            asn1Data.excludedTags[6] = true;
            asn1Data.excludedTags[9] = true;
            asn1Data.excludedTags[10] = true;
            asn1Data.excludedTags[13] = true;
            Logger.writeLog("Initialized _excludedTags map");

            Logger.writeLog("Initializing multiNestedTypes");
            asn1Data.multiNestedTypes[(Byte)Asn1Type.SEQUENCE] = true;
            asn1Data.multiNestedTypes[(Byte)((Byte)Asn1Type.SEQUENCE | (Byte)Asn1Class.CONSTRUCTED)] = true;
            asn1Data.multiNestedTypes[(Byte)Asn1Type.SET] = true;
            asn1Data.multiNestedTypes[(Byte)((Byte)Asn1Type.SET | (Byte)Asn1Class.CONSTRUCTED)] = true;
            Logger.writeLog("Initialized multiNestedTypes");
            Logger.writeLog("Constructing AsnInternalMap object and assigning to asn1Data.currentPosition");
            asn1Data.currentPosition = new AsnInternalMap();
            Logger.writeLog("Constructed AsnInternalMap object and assigning to asn1Data.currentPosition");

            Logger.writeLog("Setting asn1Data._offsetMap[0]");
            asn1Data.offsetMap[0] = asn1Data.currentPosition;
            Logger.writeLog("Finished Setting asn1Data._offsetMap[0]");
        }

        public static void Initialize(Asn1Data asn1Data, Byte[] raw, Int32 pOffset)
        {
            Logger.writeLog("Initialize-1");
            asn1Data.IsConstructed = false;
            if (raw != null)
            {
                Logger.writeLog("Initialize-2");
                asn1Data.RawData = raw;
            }
            Logger.writeLog("Initialize-3");
            asn1Data.Offset = pOffset;
            asn1Data.Tag = asn1Data.RawData[asn1Data.Offset];
            Logger.writeLog("Initialize-4");
            CalculateLength(asn1Data);
            Logger.writeLog("Initialize-5");
            // strip possible unnecessary bytes
            if (raw != null && asn1Data.TagLength != asn1Data.RawData.Length)
            {
                Logger.writeLog("Initialize-6");
                asn1Data.RawData = raw.Take(asn1Data.TagLength);
                Logger.writeLog("Initialize-7");
            }
            Logger.writeLog("Initialize-8");
            GetTagName(asn1Data, asn1Data.Tag);
            Logger.writeLog("Initialize-9");
            // 0 Tag is reserved for BER and is not available in DER
            if (asn1Data.Tag == 0)
            {
                Logger.writeLog("Initialize-10");
                Logger.writeLog("ERROR-Invalid tag");
                return;
                //throw new Asn1InvalidTagException(asn1Data.Offset);
            }
            Logger.writeLog("Initialize-11");
            if (asn1Data.PayloadLength == 0)
            {
                Logger.writeLog("Initialize-12");
                int rawDataLength = asn1Data.RawData.Length;
                int offsetAndTagLength = asn1Data.Offset + asn1Data.TagLength;
                if (offsetAndTagLength == rawDataLength)
                {
                    Logger.writeLog("Initialize-13");
                    asn1Data.NextOffset = 0;
                }
                else
                {
                    Logger.writeLog("Initialize-14");
                    asn1Data.NextOffset = offsetAndTagLength;
                }

                Logger.writeLog("Initialize-15");
                // TODO check this
                if (asn1Data.currentPosition.LevelEnd == 0 ||
                    asn1Data.Offset - asn1Data.currentPosition.LevelStart + asn1Data.TagLength == asn1Data.currentPosition.LevelEnd)
                {
                    Logger.writeLog("Initialize-16");
                    asn1Data.NextCurrentLevelOffset = 0;
                }
                else
                {
                    Logger.writeLog("Initialize-17");
                    asn1Data.NextCurrentLevelOffset = asn1Data.NextOffset;
                }
                Logger.writeLog("Initialize-18");
                //NextCurrentLevelOffset = NextOffset;
                return;
            }

            Logger.writeLog("Initialize-19");
            ParseNestedType(asn1Data);
            Logger.writeLog("Initialize-20");
            if (asn1Data.Offset - asn1Data.currentPosition.LevelStart + asn1Data.TagLength < asn1Data.currentPosition.LevelEnd)
            {
                Logger.writeLog("Initialize-21");
                asn1Data.NextCurrentLevelOffset = asn1Data.Offset + asn1Data.TagLength;
            }
            else
            {
                Logger.writeLog("Initialize-21");
                asn1Data.NextCurrentLevelOffset = 0;
            }

            if (asn1Data.IsConstructed)
            {
                Logger.writeLog("Initialize-23");
                if (asn1Data.Tag == 3)
                {
                    Logger.writeLog("Initialize-24");
                    asn1Data.NextOffset = asn1Data.PayloadStartOffset + 1;
                }
                else
                {
                    Logger.writeLog("Initialize-25");
                    asn1Data.NextOffset = asn1Data.PayloadStartOffset;
                }
            }
            else
            {
                Logger.writeLog("Initialize-26");
                if (asn1Data.Offset + asn1Data.TagLength < asn1Data.RawData.Length)
                {
                    Logger.writeLog("Initialize-27");
                    asn1Data.NextOffset = asn1Data.Offset + asn1Data.TagLength;
                }
                else
                {
                    Logger.writeLog("Initialize-28");
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
                    // throw new OverflowException("Data length is too large.");
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
            Logger.writeLog("ParseNestedType-1");
            if (asn1Data.excludedTags.HasKey(asn1Data.Tag) || asn1Data.PayloadLength < 2)
            {
                Logger.writeLog("ParseNestedType-2");
                return;
            }
            Logger.writeLog("ParseNestedType-3");
            Int64 pstart = asn1Data.PayloadStartOffset;
            Int32 plength = asn1Data.PayloadLength;

            Storage.Put(Storage.CurrentContext, "asn1Data.Tag", asn1Data.Tag);
            Storage.Put(Storage.CurrentContext, "pstart", pstart);
            Storage.Put(Storage.CurrentContext, "plength", plength);

            if (asn1Data.Tag == 3)
            {
                Logger.writeLog("ParseNestedType-4");
                pstart = asn1Data.PayloadStartOffset + 1;
                plength = asn1Data.PayloadLength - 1;
                Logger.writeLog("ParseNestedType-5");
            }

            if (asn1Data.multiNestedTypes.HasKey(asn1Data.Tag) ||
                (asn1Data.Tag & (Byte)Asn1Class.CONSTRUCTED) > 0)
            {
                Logger.writeLog("ParseNestedType-6");
                asn1Data.IsConstructed = true;
                if (!asn1Data.offsetMap.HasKey(pstart))
                {
                    Logger.writeLog("ParseNestedType-7");
                    PredictResult predictResult = Predict(asn1Data, pstart, plength, true);
                    asn1Data.childCount = predictResult.estimatedChildCount;
                    Logger.writeLog("ParseNestedType-8");
                }
                Logger.writeLog("ParseNestedType-9");
                asn1Data.isTaggedConstructed = false;
                return;
            }
            Logger.writeLog("ParseNestedType-10");
            if (asn1Data.Tag > 0 && asn1Data.Tag < (Byte)Asn1Type.TAG_MASK)
            {
                Logger.writeLog("ParseNestedType-11");
                PredictResult predictResult = Predict(asn1Data, pstart, plength, false);
                Logger.writeLog("ParseNestedType-12");
                asn1Data.childCount = predictResult.estimatedChildCount;
                asn1Data.IsConstructed = predictResult.result;
                Logger.writeLog("ParseNestedType-13");
                // reiterate again and build map for children
                if (asn1Data.IsConstructed && !asn1Data.offsetMap.HasKey(pstart))
                {
                    Logger.writeLog("ParseNestedType-14");
                    PredictResult predictResultOther = Predict(asn1Data, pstart, plength, false);
                    asn1Data.childCount = predictResultOther.estimatedChildCount;
                    Logger.writeLog("ParseNestedType-15");
                }
                Logger.writeLog("ParseNestedType-16");
            }
            Logger.writeLog("ParseNestedType-17");
            asn1Data.isTaggedConstructed = false;
        }
        public class PredictResult
        {
            public Boolean result;
            public Int32 estimatedChildCount;
        }
        static PredictResult Predict(Asn1Data asn1Data, Int64 start, Int32 projectedLength, bool assignMap)
        {
            Logger.writeLog("Predict-1");
            Int64 levelStart = start;
            Int64 sum = 0;
            PredictResult predictResult = new PredictResult();
            predictResult.estimatedChildCount = 0;
            Logger.writeLog("Predict-2");
            do
            {
                Logger.writeLog("Predict-3");
                if (start < 0 || start >= asn1Data.RawData.Length || asn1Data.RawData[start] == 0)
                {
                    Logger.writeLog("Predict-4");
                    predictResult.result = false;
                    return predictResult;
                }
                Logger.writeLog("Predict-5");
                Int64 pl = CalculatePredictLength(asn1Data, start);
                sum += pl;
                Logger.writeLog("Predict-6");
                if (assignMap && sum <= projectedLength)
                {
                    Logger.writeLog("Predict-7");
                    asn1Data.offsetMap[start] = new AsnInternalMap { LevelStart = levelStart, LevelEnd = projectedLength };
                }
                Logger.writeLog("Predict-8");
                start += pl;
                predictResult.estimatedChildCount++;
            } while (sum < projectedLength);
            Logger.writeLog("Predict-9");
            if (sum != projectedLength)
            {
                Logger.writeLog("Predict-10");
                predictResult.estimatedChildCount = 0;
            }
            Logger.writeLog("Predict-11");
            predictResult.result = sum == projectedLength;
            Logger.writeLog("Predict-12");
            return predictResult;
        }
        static Int64 CalculatePredictLength(Asn1Data asn1Data, Int64 offset)
        {
            Logger.writeLog("CalculatePredictLength-1");
            if (offset + 1 >= asn1Data.RawData.Length || offset < 0)
            {
                Logger.writeLog("CalculatePredictLength-2");
                return Int32.MaxValue;
            }
            Logger.writeLog("CalculatePredictLength-3");
            if (asn1Data.RawData[offset + 1] < 128)
            {
                Logger.writeLog("CalculatePredictLength-4");
                return asn1Data.RawData[offset + 1] + 2;
            }
            Logger.writeLog("CalculatePredictLength-5");
            Int32 lengthbytes = asn1Data.RawData[offset + 1] - 128;
            Logger.writeLog("CalculatePredictLength-6");
            // max length can be encoded by using 4 bytes.
            if (lengthbytes > 4)
            {
                Logger.writeLog("CalculatePredictLength-7");
                return Int32.MaxValue;
            }
            Logger.writeLog("CalculatePredictLength-8");
            Int32 ppayloadLength = asn1Data.RawData[offset + 2];
            Logger.writeLog("CalculatePredictLength-9");
            for (Int64 i = offset + 3; i < offset + 2 + lengthbytes; i++)
            {
                Logger.writeLog("CalculatePredictLength-10");
                ppayloadLength = (ppayloadLength << 8) | asn1Data.RawData[i];
            }
            Logger.writeLog("CalculatePredictLength-11");
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
                Logger.writeLog("Not Found Value");
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
                //throw new InvalidDataException("The data is invalid.");
            }

            // if (!asn1Data.tmpHTable.HasKey(asn1Data.Tag))
            {
                // throw new Asn1InvalidTagException();
            }
        }
        public static Byte[] GetHeader(Asn1Data asn1Data)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Data.RawData, asn1Data.Offset, asn1Data.PayloadStartOffset - asn1Data.Offset);
            //return asn1Data.RawData.Take(asn1Data.PayloadStartOffset - asn1Data.Offset);
            //Byte[] newArray = new Byte[asn1Data.PayloadStartOffset - asn1Data.Offset];
            // Array.Copy(asn1Data.RawData, 0, newArray, asn1Data.Offset, asn1Data.PayloadStartOffset - asn1Data.Offset);
            // return newArray;
            // return asn1Data.RawData.Skip(asn1Data.Offset).Take(asn1Data.PayloadStartOffset - asn1Data.Offset).ToArray();
        }
        public static Byte[] GetPayload(Asn1Data asn1Data)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Data.RawData, asn1Data.PayloadStartOffset, asn1Data.PayloadLength);
            //  return asn1Data.RawData.Skip(asn1Data.PayloadStartOffset).Take(asn1Data.PayloadLength).ToArray();
        }
        public static Byte[] GetTagRawData(Asn1Data asn1Data)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Data.RawData, asn1Data.Offset, asn1Data.TagLength);
            // return asn1Data.RawData.Skip(asn1Data.Offset).Take(asn1Data.TagLength).ToArray();
        }
        public static Int32 GetNestedNodeCount(Asn1Data asn1Data)
        {
            return asn1Data.IsConstructed ? asn1Data.childCount : 0;
        }
        public static Boolean MoveNext(Asn1Data asn1Data)
        {
            Logger.writeLog("MoveNext-1");
            if (asn1Data.NextOffset == 0)
            {
                Logger.writeLog("MoveNext-2");
                return false;
            }
            //projectedIterationSize = _offsetMap[NextOffset];
            Logger.writeLog("MoveNext-3");
            asn1Data.currentPosition = asn1Data.offsetMap[asn1Data.NextOffset];
            Logger.writeLog("MoveNext-4");
            Initialize(asn1Data, null, asn1Data.NextOffset);
            Logger.writeLog("MoveNext-5");
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
    public class Asn1GeneralizedTime
    {
        long tagValue;
        long tagValueDateTime;
        TimeZoneInfo zoneInfo;
        public String tagName = "Generalized Time";
        public Byte Tag;
        public String TagName;
        public Byte[] RawData;
        public static Asn1GeneralizedTime FromRawData(Byte[] rawData)
        {
            if (rawData[0] != (Byte)Asn1Type.Generalizedtime)
            {
                //throw new Asn1InvalidTagException("Invalid Tag");
            }
            Asn1GeneralizedTime asn1GeneralizedTime = new Asn1GeneralizedTime();
            asn1GeneralizedTime.tagName = "Generalized Time";
            asn1GeneralizedTime.RawData = rawData;
            return asn1GeneralizedTime;
        }

        static Asn1Data Decode(Asn1Data asn1Data, Asn1GeneralizedTime asn1GeneralizedTime)
        {
            Init(asn1Data, asn1GeneralizedTime);
            asn1GeneralizedTime.tagValue = DateTimeUtils.Decode(asn1Data);
            return asn1Data;
        }

        static void Init(Asn1Data asn1Data, Asn1GeneralizedTime asn1GeneralizedTime)
        {
            asn1GeneralizedTime.Tag = asn1Data.Tag;
            asn1GeneralizedTime.TagName = asn1Data.TagName;
            asn1GeneralizedTime.RawData = Asn1Parser.GetTagRawData(asn1Data);
        }

        /*public Asn1GeneralizedTime(Byte[] rawData) : base(rawData) {
            if (rawData[0] != tag) {
                throw new Asn1InvalidTagException(String.Format("Invalid Tag", tagName));
            }
            m_decode(rawData);
        }*/
        public long Value
        {
            get { return tagValue; }
        }
        public TimeZoneInfo ZoneInfo
        {
            get { return zoneInfo; }
        }
        /*void m_decode(Byte[] rawData) {
            asn1Data asn = new asn1Data(rawData);
            Init(asn);
            tagValue = DateTimeUtils.Decode(asn, out zoneInfo);
        }*/
        /* protected void Init(asn1Data asn)
         {
             Tag = asn.Tag;
             TagName = asn.TagName;
             RawData = asn.GetTagRawData();
         }*/

        public static long Decode(Asn1Data asn1Data)
        {
            if (asn1Data == null) {
                Logger.writeLog("Invalid asn1 Data - null");
                return -1;
            }
            if (asn1Data.Tag != (Byte)Asn1Type.Generalizedtime)
            {
                Logger.writeLog("Unsupported Tag");
                return -1;
            }
            return DateTimeUtils.Decode(asn1Data);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1
{
    public class Asn1ReaderT
    {
        public static void initMembers(Asn1Reader asn1Reader)
        {
            Logger.writeLog("(Start)initMembers");
            asn1Reader.excludedTags = new Map<byte, bool>();
            asn1Reader.offsetMap = new Map<Int64, AsnInternalMap>();
            asn1Reader.multiNestedTypes = new Map<byte, bool>();
            asn1Reader.tmpHTable = new Map<byte, bool>();
            Logger.writeLog("(End)initMembers");

            Logger.writeLog("Initializing _excludedTags map");
            asn1Reader.excludedTags[0] = true;
            asn1Reader.excludedTags[1] = true;
            asn1Reader.excludedTags[2] = true;
            asn1Reader.excludedTags[5] = true;
            asn1Reader.excludedTags[6] = true;
            asn1Reader.excludedTags[9] = true;
            asn1Reader.excludedTags[10] = true;
            asn1Reader.excludedTags[13] = true;
            Logger.writeLog("Initialized _excludedTags map");

            Logger.writeLog("Initializing multiNestedTypes");
            asn1Reader.multiNestedTypes[(Byte)Asn1Type.SEQUENCE] = true;
            asn1Reader.multiNestedTypes[(Byte)((Byte)Asn1Type.SEQUENCE | (Byte)Asn1Class.CONSTRUCTED)] = true;
            asn1Reader.multiNestedTypes[(Byte)Asn1Type.SET] = true;
            asn1Reader.multiNestedTypes[(Byte)((Byte)Asn1Type.SET | (Byte)Asn1Class.CONSTRUCTED)] = true;
            Logger.writeLog("Initialized multiNestedTypes");
            Logger.writeLog("Constructing AsnInternalMap object and assigning to asn1Reader.currentPosition");
            asn1Reader.currentPosition = new AsnInternalMap();
            Logger.writeLog("Constructed AsnInternalMap object and assigning to asn1Reader.currentPosition");

            Logger.writeLog("Setting asn1Reader._offsetMap[0]");
            asn1Reader.offsetMap[0] = asn1Reader.currentPosition;
            Logger.writeLog("Finished Setting asn1Reader._offsetMap[0]");
        }
        public static Asn1Reader ParseFromRawData(byte[] rawData)
        {
            Logger.writeLog("(Start)FromRawData - Byte[]");
            Asn1Reader asn1Reader = FromRawData(rawData, 0);
            Logger.writeLog("(End)FromRawData - Byte[]");
            return asn1Reader;
        }
        public static Asn1Reader FromRawData(Byte[] rawData, Int32 offset)
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

            Logger.writeLog("Constructing asn1Reader object");
            Asn1Reader asn1Reader = new Asn1Reader();
            Logger.writeLog("Constructed asn1Reader object");
            initMembers(asn1Reader);

            Logger.writeLog("Calling Initialize with asn1Reader,rawData and offset");
            Initialize(asn1Reader, rawData, offset);
            Logger.writeLog("Called Initialize with asn1Reader,rawData and offset");
            Logger.writeLog("(End)FromRawData - Byte[],Int32");
            return asn1Reader;
        }
        public static void Initialize(Asn1Reader asn1Reader, Byte[] raw, Int32 pOffset)
        {
            Logger.writeLog("Initialize-1");
            asn1Reader.IsConstructed = false;
            if (raw != null)
            {
                Logger.writeLog("Initialize-2");
                asn1Reader.RawData = raw;
            }
            Logger.writeLog("Initialize-3");
            asn1Reader.Offset = pOffset;
            asn1Reader.Tag = asn1Reader.RawData[asn1Reader.Offset];
            Logger.writeLog("Initialize-4");
            CalculateLength(asn1Reader);
            Logger.writeLog("Initialize-5");
            // strip possible unnecessary bytes
            if (raw != null && asn1Reader.TagLength != asn1Reader.RawData.Length)
            {
                Logger.writeLog("Initialize-6");
                asn1Reader.RawData = raw.Take(asn1Reader.TagLength);
                Logger.writeLog("Initialize-7");
            }
            Logger.writeLog("Initialize-8");
            GetTagName(asn1Reader, asn1Reader.Tag);
            Logger.writeLog("Initialize-9");
            // 0 Tag is reserved for BER and is not available in DER
            if (asn1Reader.Tag == 0)
            {
                Logger.writeLog("Initialize-10");
                Logger.writeLog("ERROR-Invalid tag");
                return;
                //throw new Asn1InvalidTagException(asn1Reader.Offset);
            }
            Logger.writeLog("Initialize-11");
            if (asn1Reader.PayloadLength == 0)
            {
                Logger.writeLog("Initialize-12");
                int rawDataLength = asn1Reader.RawData.Length;
                int offsetAndTagLength = asn1Reader.Offset + asn1Reader.TagLength;
                if (offsetAndTagLength == rawDataLength)
                {
                    Logger.writeLog("Initialize-13");
                    asn1Reader.NextOffset = 0;
                }
                else
                {
                    Logger.writeLog("Initialize-14");
                    asn1Reader.NextOffset = offsetAndTagLength;
                }

                Logger.writeLog("Initialize-15");
                // TODO check this
                if (asn1Reader.currentPosition.LevelEnd == 0 ||
                    asn1Reader.Offset - asn1Reader.currentPosition.LevelStart + asn1Reader.TagLength == asn1Reader.currentPosition.LevelEnd)
                {
                    Logger.writeLog("Initialize-16");
                    asn1Reader.NextCurrentLevelOffset = 0;
                }
                else
                {
                    Logger.writeLog("Initialize-17");
                    asn1Reader.NextCurrentLevelOffset = asn1Reader.NextOffset;
                }
                Logger.writeLog("Initialize-18");
                //NextCurrentLevelOffset = NextOffset;
                return;
            }

            Logger.writeLog("Initialize-19");
            ParseNestedType(asn1Reader);
            Logger.writeLog("Initialize-20");
            if (asn1Reader.Offset - asn1Reader.currentPosition.LevelStart + asn1Reader.TagLength < asn1Reader.currentPosition.LevelEnd)
            {
                Logger.writeLog("Initialize-21");
                asn1Reader.NextCurrentLevelOffset = asn1Reader.Offset + asn1Reader.TagLength;
            }
            else
            {
                Logger.writeLog("Initialize-21");
                asn1Reader.NextCurrentLevelOffset = 0;
            }

            if (asn1Reader.IsConstructed)
            {
                Logger.writeLog("Initialize-23");
                if (asn1Reader.Tag == 3)
                {
                    Logger.writeLog("Initialize-24");
                    asn1Reader.NextOffset = asn1Reader.PayloadStartOffset + 1;
                }
                else
                {
                    Logger.writeLog("Initialize-25");
                    asn1Reader.NextOffset = asn1Reader.PayloadStartOffset;
                }
            }
            else
            {
                Logger.writeLog("Initialize-26");
                if (asn1Reader.Offset + asn1Reader.TagLength < asn1Reader.RawData.Length)
                {
                    Logger.writeLog("Initialize-27");
                    asn1Reader.NextOffset = asn1Reader.Offset + asn1Reader.TagLength;
                }
                else
                {
                    Logger.writeLog("Initialize-28");
                    asn1Reader.NextOffset = 0;
                }
            }
        }
        static void CalculateLength(Asn1Reader asn1Reader)
        {
            if (asn1Reader.RawData[asn1Reader.Offset + 1] < 128)
            {
                asn1Reader.PayloadStartOffset = asn1Reader.Offset + 2;
                asn1Reader.PayloadLength = asn1Reader.RawData[asn1Reader.Offset + 1];
                asn1Reader.TagLength = asn1Reader.PayloadLength + 2;
            }
            else
            {
                Int32 lengthbytes = asn1Reader.RawData[asn1Reader.Offset + 1] - 128;
                // max length can be encoded by using 4 bytes.
                if (lengthbytes > 4)
                {
                    Logger.writeLog("ERROR-Data length is too large.");
                    // throw new OverflowException("Data length is too large.");
                }
                asn1Reader.PayloadStartOffset = asn1Reader.Offset + 2 + lengthbytes;
                asn1Reader.PayloadLength = asn1Reader.RawData[asn1Reader.Offset + 2];
                for (Int32 i = asn1Reader.Offset + 3; i < asn1Reader.PayloadStartOffset; i++)
                {
                    asn1Reader.PayloadLength = (asn1Reader.PayloadLength << 8) | asn1Reader.RawData[i];
                }
                asn1Reader.TagLength = asn1Reader.PayloadLength + lengthbytes + 2;
            }
        }
        static void GetTagName(Asn1Reader asn1Reader, Byte tag)
        {
            asn1Reader.TagName = "undefined";
            /*
            Asn1Type type = ((Asn1Type)(tag & 31));
             if ((tag & (Byte)Asn1Class.PRIVATE) != 0) {
                 switch (tag & (Byte)Asn1Class.PRIVATE) {
                     case (Byte)Asn1Class.CONTEXT_SPECIFIC:
                         asn1Reader.TagName = "CONTEXT SPECIFIC (" + (tag & 31) + ")";
                         asn1Reader.isTaggedConstructed = (tag & (Byte)Asn1Class.CONSTRUCTED) > 0;
                         break;
                     case (Byte)Asn1Class.APPLICATION:
                         asn1Reader.TagName = "APPLICATION (" + (tag & 31) + ")";
                         break;
                     case (Byte)Asn1Class.PRIVATE:
                         asn1Reader.TagName = "PRIVATE (" + (tag & 31) + ")";
                         break;
                     case (Byte)Asn1Class.CONSTRUCTED:
                         asn1Reader.TagName = "CONSTRUCTED (" + (tag & 31) + ")";
                         break;
            }
         } else {
                 asn1Reader.TagName = ((Asn1Type)(tag & 31))+"";
             }*/
        }
        static void ParseNestedType(Asn1Reader asn1Reader)
        {
            // processing rules (assuming zero-based bits):
            // if bit 5 is set to "1", or the type is SEQUENCE/SET -- the type is constructed. Unroll nested types.
            // if bit 5 is set to "0", attempt to resolve nested types only for UNIVERSAL tags.
            Logger.writeLog("ParseNestedType-1");
            if (asn1Reader.excludedTags.HasKey(asn1Reader.Tag) || asn1Reader.PayloadLength < 2)
            {
                Logger.writeLog("ParseNestedType-2");
                return;
            }
            Logger.writeLog("ParseNestedType-3");
            Int64 pstart = asn1Reader.PayloadStartOffset;
            Int32 plength = asn1Reader.PayloadLength;

            Storage.Put(Storage.CurrentContext, "asn1Reader.Tag", asn1Reader.Tag);
            Storage.Put(Storage.CurrentContext, "pstart", pstart);
            Storage.Put(Storage.CurrentContext, "plength", plength);

            if (asn1Reader.Tag == 3)
            {
                Logger.writeLog("ParseNestedType-4");
                pstart = asn1Reader.PayloadStartOffset + 1;
                plength = asn1Reader.PayloadLength - 1;
                Logger.writeLog("ParseNestedType-5");
            }

            if (asn1Reader.multiNestedTypes.HasKey(asn1Reader.Tag) ||
                (asn1Reader.Tag & (Byte)Asn1Class.CONSTRUCTED) > 0)
            {
                Logger.writeLog("ParseNestedType-6");
                asn1Reader.IsConstructed = true;
                if (!asn1Reader.offsetMap.HasKey(pstart))
                {
                    Logger.writeLog("ParseNestedType-7");
                    PredictResult predictResult = Predict(asn1Reader, pstart, plength, true);
                    asn1Reader.childCount = predictResult.estimatedChildCount;
                    Logger.writeLog("ParseNestedType-8");
                }
                Logger.writeLog("ParseNestedType-9");
                asn1Reader.isTaggedConstructed = false;
                return;
            }
            Logger.writeLog("ParseNestedType-10");
            if (asn1Reader.Tag > 0 && asn1Reader.Tag < (Byte)Asn1Type.TAG_MASK)
            {
                Logger.writeLog("ParseNestedType-11");
                PredictResult predictResult = Predict(asn1Reader, pstart, plength, false);
                Logger.writeLog("ParseNestedType-12");
                asn1Reader.childCount = predictResult.estimatedChildCount;
                asn1Reader.IsConstructed = predictResult.result;
                Logger.writeLog("ParseNestedType-13");
                // reiterate again and build map for children
                if (asn1Reader.IsConstructed && !asn1Reader.offsetMap.HasKey(pstart))
                {
                    Logger.writeLog("ParseNestedType-14");
                    PredictResult predictResultOther = Predict(asn1Reader, pstart, plength, false);
                    asn1Reader.childCount = predictResultOther.estimatedChildCount;
                    Logger.writeLog("ParseNestedType-15");
                }
                Logger.writeLog("ParseNestedType-16");
            }
            Logger.writeLog("ParseNestedType-17");
            asn1Reader.isTaggedConstructed = false;
        }
        public class PredictResult
        {
            public Boolean result;
            public Int32 estimatedChildCount;
        }
        static PredictResult Predict(Asn1Reader asn1Reader, Int64 start, Int32 projectedLength, bool assignMap)
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
                if (start < 0 || start >= asn1Reader.RawData.Length || asn1Reader.RawData[start] == 0)
                {
                    Logger.writeLog("Predict-4");
                    predictResult.result = false;
                    return predictResult;
                }
                Logger.writeLog("Predict-5");
                Int64 pl = CalculatePredictLength(asn1Reader, start);
                sum += pl;
                Logger.writeLog("Predict-6");
                if (assignMap && sum <= projectedLength)
                {
                    Logger.writeLog("Predict-7");
                    asn1Reader.offsetMap[start] = new AsnInternalMap { LevelStart = levelStart, LevelEnd = projectedLength };
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
        static Int64 CalculatePredictLength(Asn1Reader asn1Reader, Int64 offset)
        {
            Logger.writeLog("CalculatePredictLength-1");
            if (offset + 1 >= asn1Reader.RawData.Length || offset < 0)
            {
                Logger.writeLog("CalculatePredictLength-2");
                return Int32.MaxValue;
            }
            Logger.writeLog("CalculatePredictLength-3");
            if (asn1Reader.RawData[offset + 1] < 128)
            {
                Logger.writeLog("CalculatePredictLength-4");
                return asn1Reader.RawData[offset + 1] + 2;
            }
            Logger.writeLog("CalculatePredictLength-5");
            Int32 lengthbytes = asn1Reader.RawData[offset + 1] - 128;
            Logger.writeLog("CalculatePredictLength-6");
            // max length can be encoded by using 4 bytes.
            if (lengthbytes > 4)
            {
                Logger.writeLog("CalculatePredictLength-7");
                return Int32.MaxValue;
            }
            Logger.writeLog("CalculatePredictLength-8");
            Int32 ppayloadLength = asn1Reader.RawData[offset + 2];
            Logger.writeLog("CalculatePredictLength-9");
            for (Int64 i = offset + 3; i < offset + 2 + lengthbytes; i++)
            {
                Logger.writeLog("CalculatePredictLength-10");
                ppayloadLength = (ppayloadLength << 8) | asn1Reader.RawData[i];
            }
            Logger.writeLog("CalculatePredictLength-11");
            // 2 -- transitional + tag
            return ppayloadLength + lengthbytes + 2;
        }
        static Boolean MoveAndExpectTypesWithMoveNextCurrentLevel(Asn1Reader asn1Reader, params Byte[] expectedTypes)
        {
            if (expectedTypes == null) { return false; }

            foreach (Byte tag in expectedTypes)
            {
                asn1Reader.tmpHTable[tag] = true;
            }
            if (!MoveNextCurrentLevel(asn1Reader)) { return false; }

            if (!asn1Reader.tmpHTable.HasKey(asn1Reader.Tag))
            {
                Logger.writeLog("Not Found Value");
                return false;
                //throw new Asn1InvalidTagException();
            }
            return true;
        }
        static void MoveAndExpectTypesWithMoveNext(Asn1Reader asn1Reader, params Byte[] expectedTypes)
        {
            if (expectedTypes == null) { throw new ArgumentNullException(nameof(expectedTypes)); }
            foreach (Byte tag in expectedTypes)
            {
                asn1Reader.tmpHTable[tag] = true;
            }
            if (!MoveNext(asn1Reader))
            {
                //throw new InvalidDataException("The data is invalid.");
            }

            // if (!asn1Reader.tmpHTable.HasKey(asn1Reader.Tag))
            {
                // throw new Asn1InvalidTagException();
            }
        }
        public static Byte[] GetHeader(Asn1Reader asn1Reader)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Reader.RawData, asn1Reader.Offset, asn1Reader.PayloadStartOffset - asn1Reader.Offset);
            //return asn1Reader.RawData.Take(asn1Reader.PayloadStartOffset - asn1Reader.Offset);
            //Byte[] newArray = new Byte[asn1Reader.PayloadStartOffset - asn1Reader.Offset];
            // Array.Copy(asn1Reader.RawData, 0, newArray, asn1Reader.Offset, asn1Reader.PayloadStartOffset - asn1Reader.Offset);
            // return newArray;
            // return asn1Reader.RawData.Skip(asn1Reader.Offset).Take(asn1Reader.PayloadStartOffset - asn1Reader.Offset).ToArray();
        }
        public static Byte[] GetPayload(Asn1Reader asn1Reader)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Reader.RawData, asn1Reader.PayloadStartOffset, asn1Reader.PayloadLength);
            //  return asn1Reader.RawData.Skip(asn1Reader.PayloadStartOffset).Take(asn1Reader.PayloadLength).ToArray();
        }
        public static Byte[] GetTagRawData(Asn1Reader asn1Reader)
        {
            return Neo.SmartContract.Framework.Helper.Range(asn1Reader.RawData, asn1Reader.Offset, asn1Reader.TagLength);
            // return asn1Reader.RawData.Skip(asn1Reader.Offset).Take(asn1Reader.TagLength).ToArray();
        }
        public static Int32 GetNestedNodeCount(Asn1Reader asn1Reader)
        {
            return asn1Reader.IsConstructed ? asn1Reader.childCount : 0;
        }
        public static Boolean MoveNext(Asn1Reader asn1Reader)
        {
            Logger.writeLog("MoveNext-1");
            if (asn1Reader.NextOffset == 0)
            {
                Logger.writeLog("MoveNext-2");
                return false;
            }
            //projectedIterationSize = _offsetMap[NextOffset];
            Logger.writeLog("MoveNext-3");
            asn1Reader.currentPosition = asn1Reader.offsetMap[asn1Reader.NextOffset];
            Logger.writeLog("MoveNext-4");
            Initialize(asn1Reader, null, asn1Reader.NextOffset);
            Logger.writeLog("MoveNext-5");
            return true;
        }
        public static void MoveNextAndExpectTags(Asn1Reader asn1Reader, params Byte[] expectedTags)
        {
            MoveAndExpectTypesWithMoveNext(asn1Reader, expectedTags);
        }
        public static Boolean MoveNextCurrentLevel(Asn1Reader asn1Reader)
        {
            if (asn1Reader.NextCurrentLevelOffset == 0) { return false; }
            asn1Reader.currentPosition = asn1Reader.offsetMap[asn1Reader.NextCurrentLevelOffset];
            Initialize(asn1Reader, null, asn1Reader.NextCurrentLevelOffset);
            return true;
        }
        public static void MoveNextCurrentLevelAndExpectTags(Asn1Reader asn1Reader, params Byte[] expectedTags)
        {
            MoveAndExpectTypesWithMoveNextCurrentLevel(asn1Reader, expectedTags);
        }
        public static Boolean MoveToPoisition(Asn1Reader asn1Reader, Int32 newPosition)
        {
            if (asn1Reader.offsetMap == null)
            {
                throw new InvalidOperationException();
            }
            if (asn1Reader.offsetMap[newPosition] == null)
            {
                return false;
            }
            asn1Reader.currentPosition = asn1Reader.offsetMap[newPosition];
            Initialize(asn1Reader, null, newPosition);
            return true;
        }
        public static void Reset(Asn1Reader asn1Reader)
        {
            asn1Reader.currentPosition = asn1Reader.offsetMap[0];
            Initialize(asn1Reader, null, 0);
        }
        public static Int32 BuildOffsetMap(Asn1Reader asn1Reader)
        {
            Reset(asn1Reader);
            do { } while (MoveNext(asn1Reader));
            Reset(asn1Reader);
            return 1;//asn1Reader._offsetMap.Keys.Size();
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

        static Asn1Reader Decode(Asn1Reader asn1Reader, Asn1GeneralizedTime asn1GeneralizedTime)
        {
            Init(asn1Reader, asn1GeneralizedTime);
            asn1GeneralizedTime.tagValue = DateTimeUtils.Decode(asn1Reader);
            return asn1Reader;
        }

        static void Init(Asn1Reader asn1Reader, Asn1GeneralizedTime asn1GeneralizedTime)
        {
            asn1GeneralizedTime.Tag = asn1Reader.Tag;
            asn1GeneralizedTime.TagName = asn1Reader.TagName;
            asn1GeneralizedTime.RawData = Asn1ReaderT.GetTagRawData(asn1Reader);
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
            Asn1Reader asn = new Asn1Reader(rawData);
            Init(asn);
            tagValue = DateTimeUtils.Decode(asn, out zoneInfo);
        }*/
        /* protected void Init(Asn1Reader asn)
         {
             Tag = asn.Tag;
             TagName = asn.TagName;
             RawData = asn.GetTagRawData();
         }*/

        public static long Decode(Asn1Reader asn1Reader)
        {
            if (asn1Reader == null) { throw new ArgumentNullException("asn"); }
            if (asn1Reader.Tag != (Byte)Asn1Type.Generalizedtime)
            {
                //throw new Asn1InvalidTagException("Invalid Type" + tagName);
            }
            return DateTimeUtils.Decode(asn1Reader);
        }
    }
}

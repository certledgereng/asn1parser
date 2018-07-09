using Asn1ParserContract.asn1.utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1
{
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
            if (asn1Data == null)
            {
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

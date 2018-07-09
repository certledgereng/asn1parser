﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract.asn1.utils
{
    class DateTimeUtils
    {
        public static Byte[] Encode(DateTime time, TimeZoneInfo zone, Boolean UTC, Boolean usePrecise)
        {
            Byte[] rawData = new Byte[] { };
            /*
			String suffix = String.Empty;
			String preValue;
			String format = UTC
				? UTCFormat
				: GtFormat;
			if (usePrecise) {
				suffix += String.Format(".{0:D3}", time.Millisecond);
			}
			if (zone == null) {
				preValue = time.ToUniversalTime().ToString(format) + suffix + "Z";
			} else {
				suffix += zone.BaseUtcOffset.Hours >= 0 && zone.BaseUtcOffset.Minutes >= 0
					? "-"
					: "+";
				suffix +=
					Math.Abs(zone.BaseUtcOffset.Hours).ToString("d2") +
					Math.Abs(zone.BaseUtcOffset.Minutes).ToString("d2");
				preValue = time.ToString(format) + suffix;
			}
			Byte[] rawData = new Byte[preValue.Length];
			for (Int32 index = 0; index < preValue.Length; index++) {
				Char element = preValue[index];
				rawData[index] = Convert.ToByte(element);
			}
            */
            return rawData;
        }
        // rawData is pure value without header
        public static long Decode(Asn1Reader asn)
        {
            string retString = "";
            for (Int32 i = asn.PayloadStartOffset; i < asn.PayloadStartOffset + asn.PayloadLength; i++)
            {
                retString += asn.RawData[i];
            }
            return extractDateTime(retString);
        }
        static long extractDateTime(string strValue)
        {
            /*
			Int32 delimeterIndex;
			Int32 hours, minutes;
			if (strValue.IndexOfAny(new char[] { 'Z' }) >-1) {
				delimeterIndex = strValue.IndexOfAny(new char[] { 'Z' });
				return extractZulu(strValue, delimeterIndex);
			}*/
            return 1;
            /*
			Boolean hasZone = extractZoneShift(strValue, out hours, out minutes, out delimeterIndex);
			Int32 msDelimiter;
			Int32 milliseconds = extractMilliseconds(strValue, delimeterIndex, out msDelimiter);
			DateTime retValue = extractDateTime(strValue, msDelimiter, delimeterIndex);
			retValue = retValue.AddMilliseconds(milliseconds);
            return retValue;*/
        }
        static long extractZulu(String strValue, Int32 zoneDelimeter)
        {
            return 1;
            /*
            switch (zoneDelimeter) {
				case 12:
					return DateTime.ParseExact(strValue.Replace("Z", null), UTCFormat, null).ToLocalTime();
				case 16:
					return DateTime.ParseExact(strValue.Replace("Z", null), UTCPreciseFormat, null).ToLocalTime();
				case 14:
					return DateTime.ParseExact(strValue.Replace("Z", null), GtFormat, null).ToLocalTime();
				case 18:
					return DateTime.ParseExact(strValue.Replace("Z", null), GtPreciseFormat, null).ToLocalTime();
				default:
					throw new ArgumentException("Time zone suffix is not valid.");      
			}*/
        }
        /*
		static Boolean extractZoneShift(String strValue, Int32 hours, Int32 minutes, Int32 delimeterIndex) {
            if (strValue.Contains('+')) {
				delimeterIndex = strValue.IndexOf('+');
				hours = Int32.Parse(strValue.Substring(delimeterIndex, 3));
			} else if (strValue.Contains('-')) {
				delimeterIndex = strValue.IndexOf('-');
				hours = -Int32.Parse(strValue.Substring(delimeterIndex, 3));
			} else {
				hours = minutes = delimeterIndex = 0;
				return false;
			}
			minutes = strValue.Length > delimeterIndex + 3
				? -Int32.Parse(strValue.Substring(delimeterIndex + 3, 2))
				: 0;
            return true;
		}
		static Int32 extractMilliseconds(String strValue, Int32 zoneDelimeter, out Int32 msDelimeter) {
			msDelimeter = -1;
			if (!strValue.Contains(".")) { return 0; }
			msDelimeter = strValue.IndexOf('.');
			Int32 precisionLength = zoneDelimeter > 0
				? zoneDelimeter - msDelimeter - 1
				: strValue.Length - msDelimeter - 1;
			return Int32.Parse(strValue.Substring(msDelimeter + 1, precisionLength));
		}
		static DateTime extractDateTime(String strValue, Int32 msDelimeter, Int32 zoneDelimeter) {
			String rawString;
			if (msDelimeter > zoneDelimeter) {
				rawString = strValue.Substring(0, zoneDelimeter);
			} else if (msDelimeter < zoneDelimeter) {
				rawString = strValue.Substring(0, msDelimeter);
			} else {
				rawString = strValue;
			}
			switch (rawString.Length) {
				case 12:
					return DateTime.ParseExact(rawString, UTCFormat, null);
				case 14:
					return DateTime.ParseExact(rawString, GtFormat, null);
				default:
					throw new ArgumentException("Time zone suffix is not valid.");
			}
		}
		static TimeZoneInfo bindZone(Int32 hours, Int32 minutes) {
			foreach (TimeZoneInfo zone in TimeZoneInfo.GetSystemTimeZones().Where(zone => zone.BaseUtcOffset.Hours == hours && zone.BaseUtcOffset.Minutes == minutes)) {
				return zone;
			}
			return TimeZoneInfo.FindSystemTimeZoneById("Greenwich Standard Time");
		}*/
        #region Constants
        const String UTCFormat = "yyMMddHHmmss";
        const String UTCPreciseFormat = "yyMMddHHmmss.FFF";
        const String GtFormat = "yyyyMMddHHmmss";
        const String GtPreciseFormat = "yyyyMMddHHmmss.FFF";
        #endregion
    }
}

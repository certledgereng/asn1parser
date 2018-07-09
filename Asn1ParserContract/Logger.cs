using Neo.SmartContract.Framework.Services.Neo;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1ParserContract
{
    public class Logger
    {
        public static void writeLog(String log)
        {
            Runtime.Log(log);
        }
    }
}

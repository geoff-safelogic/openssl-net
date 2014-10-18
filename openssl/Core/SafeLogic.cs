using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OpenSSL.Core
{
    public class SafeLogic
    {
        static public Boolean EnableFIPSMode()
        {
            if (Native.FIPS_mode() == 1) return true;
            int rv = Native.FIPS_mode_set(1);
            return rv == 1;
        }
        static public void DisableFIPSMode()
        {
            if (Native.FIPS_mode() == 0) return;
            Native.FIPS_mode_set(0);
        }
        static public Boolean FIPSMode()
        {
            return Native.FIPS_mode() == 1;
        }
    }
}

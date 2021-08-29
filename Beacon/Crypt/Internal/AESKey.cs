using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Beacon.Crypt.Internal
{
    public class AESKey
    {
        /// <summary>
        /// ase key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// ase IV
        /// </summary>
        public string IV { get; set; }
    }
}

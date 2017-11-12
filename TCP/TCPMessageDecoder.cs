using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Codec;

namespace Com.AugustCellars.CoAP.TLS
{
    class TCPMessageDecoder : Spec.MessageDecoder18
    {
        private Int32 _itemLength;
        static private int MessageIdCounter;

        public TCPMessageDecoder(Byte[] data) : base(data)
        {
            
        }

        protected override void ReadProtocol()
        {
            Int32 length = m_reader.Read(4);        // 4 bits of length
            m_tokenLength = m_reader.Read(4);       // 4 bits of token length
            switch (length) {                       // variable size for the data length
            case 13:
                _itemLength = m_reader.Read(8) + 13;
                break;

            case 14:
                _itemLength = m_reader.Read(16) + 269;
                break;

            case 15:
                _itemLength = m_reader.Read(32) + 65805;
                break;

            default:
                _itemLength = length;
                break;
            }
            m_code = m_reader.Read(8);              // 8 bits of code
            m_id = MessageIdCounter++;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// QueueItems are used for items in the 
    /// </summary>
    public class QueueItem
    {


        private readonly byte[] _data;
        private readonly TcpSession _session;

 
        public QueueItem(TcpSession session, byte[] data)
        {
            _data = data;
            _session = session;
        }

        public byte[] Data { get { return _data; } }
        public int Length { get { return Data.Length;  } }
        public TcpSession Session { get { return _session; } }
    }
}

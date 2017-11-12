using System;

using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Threading;
using Com.AugustCellars.CoAP.Channel;
using Com.AugustCellars.CoAP;

namespace Com.AugustCellars.CoAP.TLS
{
    public class TcpSession : ISession
    {
        private TcpClient _client;
        private readonly IPEndPoint _ipEndPoint;
        private QueueItem _toSend;
        private NetworkStream _stm;

        private readonly ConcurrentQueue<QueueItem> _queue = new ConcurrentQueue<QueueItem>();

        public TcpSession(IPEndPoint ipEndPoint, QueueItem toSend)
        {
            _ipEndPoint = ipEndPoint;
            _toSend = toSend;
        }

        public TcpSession(TcpClient client)
        {
            _client = client;
            _ipEndPoint = (IPEndPoint) client.Client.RemoteEndPoint;
        }

        public ConcurrentQueue<QueueItem> Queue { get { return _queue; } }

        public NetworkStream Stream
        {
            get
            {
                if (_stm == null) _stm = _client.GetStream();
                return _stm;
            }
        }

        public IPEndPoint EndPoint {  get { return _ipEndPoint; } }

        public bool IsReliable => true;

        /// <summary>
        /// True means that it is supported, False means that it may be supported.
        /// </summary>
        public bool BlockTransfer { get; set; } = true;

        /// <summary>
        /// Max message size 
        /// </summary>
        public int MaxSendSize { get; set; } = 1152;

        public void Connect()
        {
            _client = new TcpClient(_ipEndPoint.AddressFamily);

            _client.Connect(_ipEndPoint);

            _stm = _client.GetStream();

            //  Send over the capability block

            SignalMessage signal = new SignalMessage(SignalCode.CSM);
            Option op;
            if (BlockTransfer) {
                op = Option.Create(OptionType.Signal_BlockTransfer);
                signal.AddOption(op);
            }
            
            op = Option.Create(OptionType.Signal_MaxMessageSize);
            op.IntValue = 1152; // 2048;
            signal.AddOption(op);

            byte[] data;
            TLSMessageEncoder enc = new TLSMessageEncoder();

            data = enc.Encode(signal); 

            _stm.Write(data, 0, data.Length);
            _stm.Flush();

            //  

            if (_toSend != null) {
                _stm.Write(_toSend.Data, 0, _toSend.Length);
                _stm.Flush();
                _toSend = null;
            }

            new Thread(() => StreamListener()).Start();
        }

        public void Stop()
        {
        }

        public void Release()
        {
        }

        public void Abort()
        {
            return;
        }

        private Int32 _writing;
        private readonly Object _writeLock = new Object();

        public event EventHandler<SessionEventArgs> SessionEvent;

        public void WriteData()
        {
            if (_queue.Count == 0) return;
            lock (_writeLock) {
                if (_writing > 0) return;
                _writing = 1;
            }

            while (Queue.Count > 0) {
                QueueItem q;
                if (!_queue.TryDequeue(out q)) break;

                _stm.Write(q.Data, 0, q.Data.Length);
            }

            lock (_writeLock) {
                _writing = 0;
                if (_queue.Count > 0) WriteData();
            }
        }

        private void StreamListener()
        {
            try {

                NetworkStream stream = _client.GetStream();

                byte[] bytes = new byte[2048+1024];
                int offset = 0;
                int messageSize;

                while (true) {
                    int i = stream.Read(bytes, offset, bytes.Length - offset);
                    i += offset;

                    while (i > 0) {
                        //  Do I have a full record?

                        int dataSize = (bytes[0] >> 4) & 0xf;
                        switch (dataSize) {
                            case 13:
                                messageSize = bytes[1] + 13 + 3;
                                break;

                            case 14:
                                messageSize = (bytes[1] * 256 + bytes[2]) + 269 + 4;
                                break;

                            case 15:
                                messageSize = ((bytes[1] * 256 + bytes[2]) * 256 + bytes[3]) * 256 + bytes[4] + 65805 + 6;
                                break;

                            default:
                                messageSize = dataSize + 2;
                                break;
                        }
                        messageSize += (bytes[0] & 0xf); // Add token buffer

                        if (i >= messageSize) {
                            byte[] message = new byte[messageSize];
                            Array.Copy(bytes, message, messageSize);
                            Array.Copy(bytes, messageSize, bytes, 0, i - messageSize);
                            offset = i - messageSize;
                            i -= messageSize;

                            FireDataReceived(message, EndPoint, this);
                        }
                        else {
                            break;
                        }
                    }
                }

            }
            catch (Exception e) {
                Console.WriteLine("StreamListener --> " + e.ToString());
            }
        }

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep, TcpSession tcpSession)
        {
            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null) {
                h(this, new DataReceivedEventArgs(data, ep, tcpSession));
            }
        }

    }
}

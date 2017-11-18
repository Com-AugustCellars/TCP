using System;

using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Threading;
using Com.AugustCellars.CoAP.Channel;
using Com.AugustCellars.CoAP;

namespace Com.AugustCellars.CoAP.TLS
{
    internal class TcpSession : ISession
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

        public NetworkStream Stream {
            get {
                if (_stm == null) _stm = _client.GetStream();
                return _stm;
            }
        }

        public IPEndPoint EndPoint { get { return _ipEndPoint; } }

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

            SendCSMSignal();

            //  

            if (_toSend != null) {
                _queue.Enqueue(_toSend);
                _toSend = null;
            }

            _stm.BeginRead(_buffer, 0, _buffer.Length, ReadCallback, this);

            WriteData();
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

        public void SendCSMSignal()
        {
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

            _queue.Enqueue(new QueueItem(this, data));
        }

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


        private byte[] _buffer = new byte[2048];

        public void BeginRead()
        {
            Stream.BeginRead(_buffer, 0, _buffer.Length, ReadCallback, this);
        }

        private static void ReadCallback(IAsyncResult ar)
        {
            try {
                TcpSession session = (TcpSession)ar.AsyncState;

                int cbRead = session._stm.EndRead(ar);
                session.ProcessInput(cbRead);
            }
            catch (ObjectDisposedException) {
                ; // Ignore this error
            }
        }

        private byte[] _carryOver = null;
        private void ProcessInput(int cbRead)
        {
            byte[] bytes = new byte[(_carryOver != null ? _carryOver.Length : 0) + cbRead];
            if (_carryOver != null) {
                Array.Copy(_carryOver, bytes, _carryOver.Length);
                Array.Copy(_buffer, 0, bytes, _carryOver.Length, cbRead);
            }
            else Array.Copy(_buffer, bytes, cbRead);

            int cbLeft = bytes.Length;

            while (cbLeft > 0) {
                int messageSize;

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

                if (cbLeft >= messageSize) {
                    byte[] message = new byte[messageSize];
                    int offset;
                    Array.Copy(bytes, message, messageSize);
                    Array.Copy(bytes, messageSize, bytes, 0, cbLeft - messageSize);
                    offset = cbLeft - messageSize;
                    cbLeft -= messageSize;

                    FireDataReceived(message, EndPoint, this);
                }
                else {
                    break;
                }
            }

            if (cbLeft > 0) {
                _carryOver = new byte[cbLeft];
                Array.Copy(bytes, _carryOver, cbLeft);
            }
            else {
                _carryOver = null;
            }
            _stm.BeginRead(_buffer, 0, _buffer.Length, ReadCallback, this);
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

using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Com.AugustCellars.CoAP.Channel;
using System.Threading.Tasks;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Implement TCP as a channel for the CoAP protocol
    /// </summary>
    public class TCPChannel : IChannel
    {
        private System.Net.EndPoint _localEP;
        private Int32 _port;
        private Int32 _running;
        private TcpListener _listener;

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

 
        /// <summary>
        /// Initialize a TCP channel with a random port.
        /// </summary>
        public TCPChannel() : this(0)
        { }

        /// <summary>
        /// Initialize a TCP Channel with the specific endpoint port.
        /// </summary>
        /// <param name="port"></param>
        public TCPChannel(Int32 port)
        {
            _port = port;
        }

        /// <summary>
        /// Initialize a TCP channel with an endpoint
        /// </summary>
        /// <param name="localEP"></param>
        public TCPChannel(System.Net.EndPoint localEP)
        {
            _localEP = localEP;
        }

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint
        {
            get { return _listener == null ? (_localEP ?? new IPEndPoint(IPAddress.IPv6Any, _port)) : _listener.LocalEndpoint; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public Int32 ReceiveBufferSize { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="Socket.SendBufferSize"/>.
        /// </summary>
        public Int32 SendBufferSize { get; set; }

        /// <summary>
        /// Gets or sets the size of buffer for receiving packet.
        /// The default value is <see cref="DefaultReceivePacketSize"/>.
        /// </summary>
        public Int32 ReceivePacketSize { get; set; }

        /// <inheritdoc/>
        public bool AddMulticastAddress(IPEndPoint ep)
        {
            return false;
        }

        /// <inheritdoc/>
        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0) {
                return;
            }


            if (_localEP != null) {
                IPEndPoint ipep = (IPEndPoint) _localEP;

                _listener = new TcpListener(ipep.Address, ipep.Port);
                return;
            }
            else {
                _listener = new TcpListener(IPAddress.IPv6Any, _port);
                _listener.Server.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, 0);

            }

            try {
                _listener.Start();

            }
            catch (Exception) {
                throw new Exception("Failed to start TCP connection");
            }

            _localEP = _listener.LocalEndpoint;

            StartAccepts();
        }

        /// <inheritdoc/>>
        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0) {
                return;
            }

            if (_listener != null) {
                _listener.Stop();
                _listener = null;
            }
        }

        /// <summary>
        /// We don't do anything for this right now because we don't have sessions.
        /// </summary>
        /// <param name="session"></param>
        public void Abort(ISession session)
        {
            TcpSession tcp = session as TcpSession;
            if (tcp != null) tcp.Abort();
            return;
        }

        /// <summary>
        /// We don't do anything for this right now because we don't have sessions.
        /// </summary>
        /// <param name="session"></param>
        public void Release(ISession session)
        {
            return;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Stop();
        }

        private void StartAccepts()
        {
            Task<TcpClient> taskAwaiter = _listener.AcceptTcpClientAsync();

            taskAwaiter.ContinueWith((answer) => DoAccept(answer.Result), TaskContinuationOptions.OnlyOnRanToCompletion);
        }

        private void DoAccept(TcpClient tcpClient)
        {
            TcpSession session = new TcpSession(tcpClient);

            AddSession(session);

            session.DataReceived += this.DataReceived;
            session.BeginRead();
            session.SendCSMSignal();
            session.WriteData();

            StartAccepts();
        }

        private void NewTcpClient(TcpClient soTcp)
        {

        }

        private static List<TcpSession> _sessionList = new List<TcpSession>();
        private static void AddSession(TcpSession session)
        {
            lock (_sessionList) {
                _sessionList.Add(session);
            }
        }

        private static TcpSession FindSession(IPEndPoint ipEP)
        {
            lock (_sessionList) {

                foreach (TcpSession session in _sessionList) {
                    if (session.EndPoint.Equals(ipEP))
                        return session;
                }
            }
            return null;
        }

        private void StreamListener(TcpSession soTcp)
        {
            try {

                NetworkStream stream = soTcp.Stream;

                byte[] bytes = new byte[1163];
                int offset = 0;
                int messageSize;

                //  Start by sending the capability message
                byte[] data = { 0x10, 0xE1, 0x40 };
                stream.Write(data, 0, data.Length);

                while (true) {
                    int i = stream.Read(bytes, offset, bytes.Length-offset);
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

                            FireDataReceived(message, soTcp.EndPoint, null, soTcp); // M00BUG
                        }
                        else {
                            break;
                        }
                    }
                }

            }
            catch (Exception  e) {
                Console.WriteLine("StreamListener --> " + e.ToString());
            }
        }

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep, System.Net.EndPoint endPointLocal, TcpSession tcpSession)
        {
            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null) {
                h(this, new DataReceivedEventArgs(data, ep, endPointLocal, tcpSession));
            }
        }
        
        /// <inheritdoc/>
        public void Send(byte[] data, ISession session, System.Net.EndPoint ep)
        {
            TcpSession tcpSession;
            //  Wrong code but let's get started

            try {
                if (session == null) {
                    IPEndPoint ipEP = (IPEndPoint)ep;

                    TcpSession sessionX = FindSession(ipEP);
                    if (sessionX == null) {

                        sessionX = new TcpSession(ipEP, new QueueItem(null, data));
                        sessionX.Connect();
                        AddSession(sessionX);
                    }
                    session = sessionX;
                }

                tcpSession = session as TcpSession;
                tcpSession.Queue.Enqueue(new QueueItem(tcpSession, data));
                tcpSession.WriteData();


            }
            catch (Exception e) {
                Console.WriteLine("Error in TCP Sending - " + e.ToString());
            }
        }

        /// <inheritdoc/>
        public ISession GetSession(System.Net.EndPoint ep)
        {
            IPEndPoint ipEP = (IPEndPoint)ep;

            TcpSession sessionX = FindSession(ipEP);

            return sessionX;
        }
    }
}

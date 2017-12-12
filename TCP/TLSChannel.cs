using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Com.AugustCellars.CoAP.Channel;
using System.Threading.Tasks;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Implement TLS as a channel for the CoAP protocol
    /// </summary>
    public class TLSChannel : IChannel
    {
        private System.Net.EndPoint _localEP;
        private Int32 _port;
        private Int32 _running;
        private TcpListener _listener;
        private readonly KeySet _signingKeys;
        private readonly KeySet _clientKeys;

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;


        /// <summary>
        /// Initialize a TCP channel with a random port.
        /// </summary>
        /// <param name="signingKeys">Keys the server can sign with</param>
        /// <param name="clientKeys">PSK and RPK keys for client authentication</param>
        public TLSChannel(KeySet signingKeys, KeySet clientKeys) : this(signingKeys, clientKeys, 0)
        { }

        /// <summary>
        /// Initialize a TCP Channel with the specific endpoint port.
        /// </summary>
        /// <param name="signingKeys">Keys the server can sign with</param>
        /// <param name="clientKeys">PSK and RPK keys for client authentication</param>
        /// <param name="port"></param>
        public TLSChannel(KeySet signingKeys, KeySet clientKeys, Int32 port)
        {
            _port = port;
            _signingKeys = signingKeys;
            _clientKeys = clientKeys;
        }

        /// <summary>
        /// Initialize a TCP channel with an endpoint
        /// </summary>
        /// <param name="signingKeys">Keys the server can sign with</param>
        /// <param name="clientKeys">PSK and RPK keys for client authentication</param>
        /// <param name="localEP"></param>
        public TLSChannel(KeySet signingKeys, KeySet clientKeys, System.Net.EndPoint localEP)
        {
            _localEP = localEP;
            _signingKeys = signingKeys;
            _clientKeys = clientKeys;
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
            TLSSession session = new TLSSession(tcpClient, _clientKeys, _signingKeys);

            AddSession(session);
            StartAccepts();

            session.DataReceived += this.DataReceived;
            session.Accept();

            session.BeginRead();
            session.SendCSMSignal();

        }

        private void NewTcpClient(TcpClient soTcp)
        {

        }

        private static List<TLSSession> _sessionList = new List<TLSSession>();
        private static void AddSession(TLSSession session)
        {
            lock (_sessionList) {
                _sessionList.Add(session);
            }
        }

        private static TLSSession FindSession(IPEndPoint ipEP)
        {
            lock (_sessionList) {

                foreach (TLSSession session in _sessionList) {
                    if (session.EndPoint.Equals(ipEP))
                        return session;
                }
            }
            return null;
        }

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep, TLSSession tcpSession)
        {
            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null) {
                h(this, new DataReceivedEventArgs(data, ep, tcpSession));
            }
        }
        
        /// <inheritdoc/>
        public void Send(byte[] data, ISession session, System.Net.EndPoint ep)
        {
            TLSSession tcpSession;

            try {
                if (session == null) {
                    IPEndPoint ipEP = (IPEndPoint)ep;

                    TLSSession sessionX = FindSession(ipEP);
                    if (session == null) {

                        sessionX = new TLSSession(ipEP, new QueueItem(null, data), null);
                        sessionX.DataReceived += this.DataReceived;

                        sessionX.Connect();
                        AddSession(sessionX);
                    }
                    session = sessionX;
                }

                tcpSession = session as TLSSession;
                tcpSession.Queue.Enqueue(new QueueItem(tcpSession, data));
                tcpSession.WriteData();


            }
            catch (Exception e) {
                Console.WriteLine("Error in TLS Sending - " + e.ToString());
            }
        }

        /// <inheritdoc/>
        public ISession GetSession(System.Net.EndPoint ep)
        {
            IPEndPoint ipEP = (IPEndPoint)ep;

            TLSSession sessionX = FindSession(ipEP);

            return sessionX;
        }
    }
}

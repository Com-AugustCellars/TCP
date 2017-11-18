using System;
using System.Collections.Generic;

using System.Net;
using System.Net.Sockets;
using Com.AugustCellars.CoAP.Channel;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Low level channel for DTLS when dealing only with clients.
    /// This channel will not accept any connections from other parties.
    /// </summary>
    internal class TCPClientChannel : IChannel
    {
        public const Int32 DefaultReceivePacketSize = 4096;

        private readonly System.Net.EndPoint _localEndPoint;
        private readonly int _port;

        /// <summary>
        /// Create a client only channel and use a randomly assigned port on
        /// the client UDP port.
        /// </summary>
        public TCPClientChannel() : this(0)
        {
        }

        /// <summary>
        /// Create a client only channel and use a given point
        /// </summary>
        /// <param name="port">client side UDP port</param>
        public TCPClientChannel(Int32 port)
        {
            _port = port;
        }

        /// <summary>
        /// Create a client only channel and use a given endpoint
        /// </summary>
        /// <param name="ep">client side endpoint</param>
        public TCPClientChannel(System.Net.EndPoint ep)
        {
            _localEndPoint = ep;
        }

        /// <inheritdoc/>
        public event EventHandler<DataReceivedEventArgs> DataReceived;

        /// <inheritdoc/>
        public System.Net.EndPoint LocalEndPoint {
            get => (_localEndPoint == null) ? new IPEndPoint(IPAddress.IPv6Any, _port) : null;  // M00BUG
        }

        /// <summary>
        /// Gets or sets the <see cref="Socket.ReceiveBufferSize"/>.
        /// </summary>
        public Int32 ReceiveBufferSize { get; set; } = DefaultReceivePacketSize;

        /// <summary>
        /// Gets or sets the <see cref="Socket.SendBufferSize"/>.
        /// </summary>
        public Int32 SendBufferSize { get; set; }

        /// <summary>
        /// Gets or sets the size of buffer for receiving packet.
        /// The default value is <see cref="DefaultReceivePacketSize"/>.
        /// </summary>
        public Int32 ReceivePacketSize { get; set; }

        private Int32 _running;


        /// <summary>
        /// Tell the channel to set itself up and start processing data
        /// </summary>
        public void Start()
        {
            if (System.Threading.Interlocked.CompareExchange(ref _running, 1, 0) > 0) {
                return;
            }
        }

        /// <summary>
        /// Tell the channel to stop processing data cand clean itself up.
        /// </summary>
        public void Stop()
        {
            if (System.Threading.Interlocked.Exchange(ref _running, 0) == 0)
                return;

            lock (_sessionList) {
                foreach (TcpSession session in _sessionList) {
                    session.Stop();
                }
                _sessionList.Clear();
            }
        }

        /// <summary>
        /// We don't do anything for this right now because we don't have sessions.
        /// </summary>
        /// <param name="session"></param>
        public void Abort(ISession session)
        {
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

        /// <summary>
        /// Tell the channel to release all of it's resources
        /// </summary>
        public void Dispose()
        {
            Stop();
        }

        public void Send(byte[] data, ISession session, System.Net.EndPoint ep)
        {
            try {
                //  We currently only support IP addresses with this channel.
                //  This is a restriction is enforce from BouncyCastle where
                //  that is the only end point that can be used.

                IPEndPoint ipEndPoint = (IPEndPoint)ep;
                TcpSession tcpSession = (TcpSession)session;

                if (session == null) {
                    tcpSession = FindSession(ipEndPoint);
                    if (session == null) {

                        //  Create a new session to send with if we don't already have one

                        tcpSession = new TcpSession(ipEndPoint, null /*DataReceived*/);
                        AddSession(tcpSession);

                        tcpSession.Connect();

                        tcpSession.DataReceived += DataReceived;
                    }
                }

                //  Queue the data onto the session.

                tcpSession.Queue.Enqueue(new QueueItem(null, data));
                tcpSession.WriteData();
            }
            catch (Exception e) {
#if DEBUG
                Console.WriteLine("Error in TCPClientChannel Sending - " + e.ToString());
#endif
                throw;
            }
        }

        /// <summary>
        /// Send data through the DTLS channel to other side
        /// </summary>
        /// <param name="data">Data to be sent</param>
        /// <param name="ep">Where to send it</param>
        public void Send(byte[] data, System.Net.EndPoint ep)
        {
            try {
                //  We currently only support IP addresses with this channel.
                //  This is a restriction is enforce from BouncyCastle where
                //  that is the only end point that can be used.

                IPEndPoint ipEndPoint = (IPEndPoint)ep;

                TcpSession session = FindSession(ipEndPoint);
                if (session == null) {

                    //  Create a new session to send with if we don't already have one

                    session = new TcpSession(ipEndPoint,null /* DataReceived*/ );
                    AddSession(session);

                    session.Connect();
                }

                //  Queue the data onto the session.

                session.Queue.Enqueue(new QueueItem(null, data));
                session.WriteData();
            }
            catch (Exception e) {
#if DEBUG
                Console.WriteLine("Error in DTLSClientChannel Sending - " + e.ToString());
#endif
                throw;
            }
        }

        private void ReceiveData(Object sender, DataReceivedEventArgs e)
        {
            lock (_sessionList) {
                foreach (TcpSession session in _sessionList) {
                    if (e.EndPoint.Equals(session.EndPoint)) {
                        // session.ReceiveData(sender, e);

                        return;
                    }
                }
            }
        }

        /// <summary>
        /// Keep track of all of the sessions that have been setup on this channel.
        /// </summary>
        private readonly List<TcpSession> _sessionList = new List<TcpSession>();

        private void AddSession(TcpSession session)
        {
            lock (_sessionList) {
                _sessionList.Add(session);
            }
        }

        private TcpSession FindSession(IPEndPoint ipEndPoint)
        {
            lock (_sessionList) {

                foreach (TcpSession session in _sessionList) {
                    if (session.EndPoint.Equals(ipEndPoint))
                        return session;
                }
            }
            return null;
        }


        public ISession GetSession(System.Net.EndPoint ep)
        {
            IPEndPoint ipEndPoint = (IPEndPoint)ep;
            return (ISession) FindSession(ipEndPoint);
        }
    }
}

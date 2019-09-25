using System;

using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Threading;
using Com.AugustCellars.CoAP.Channel;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.COSE;
using Org.BouncyCastle.Crypto.Tls;
using PeterO.Cbor;
using Org.BouncyCastle.Security;

namespace Com.AugustCellars.CoAP.TLS
{
    public class TLSSession : ISession, ISecureSession
    {
        private TcpClient _tcpClient;
        private readonly IPEndPoint _ipEndPoint;
        private QueueItem _toSend;
        private NetworkStream _tcpStream;
        private readonly TlsKeyPair _userKey;
        private readonly KeySet _clientKeys;
        private readonly TlsKeyPairSet _signingKeys;
        private OneKey _authKey;
        private TLSClient _tlsSession;
        private TlsServerProtocol _tlsServer;
        private TlsClientProtocol _tlsClient;
#if SUPPORT_TLS_CWT
        private KeySet CwtTrustKeySet { get; }
#endif
        public EventHandler<TlsEvent> TlsEventHandler;

        private readonly ConcurrentQueue<QueueItem> _queue = new ConcurrentQueue<QueueItem>();

        public TLSSession(IPEndPoint ipEndPoint, QueueItem toSend, TlsKeyPair tlsKey)
        {
            _ipEndPoint = ipEndPoint;
            _toSend = toSend;
            _userKey = tlsKey;
        }

        public TLSSession(IPEndPoint ipEndPoint, QueueItem toSend, KeySet clientKeys, TlsKeyPairSet signingKeys, KeySet cwtTrustKeySet = null)
        {
            _ipEndPoint = ipEndPoint;
            _toSend = toSend;
            _clientKeys = clientKeys;
            _signingKeys = signingKeys;
#if SUPPORT_TLS_CWT
            CwtTrustKeySet = cwtTrustKeySet;
#endif
        }

        public TLSSession(TcpClient tcpClient, KeySet clientKeys, TlsKeyPairSet signingKeys)
        {
            _tcpClient = tcpClient;
            _ipEndPoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
            _clientKeys = clientKeys;
            _signingKeys = signingKeys;
        }

        public ConcurrentQueue<QueueItem> Queue => _queue;

        public NetworkStream Stream => _tcpStream ?? (_tcpStream = _tcpClient.GetStream());

        public IPEndPoint EndPoint => _ipEndPoint;

        public bool IsReliable => true;

        /// <summary>
        /// True means that it is supported, False means that it may be supported.
        /// </summary>
        public bool BlockTransfer { get; set; } = true;

        /// <summary>
        /// Max message size 
        /// </summary>
        public int MaxSendSize { get; set; } = 1152;

        public OneKey AuthenticationKey => _authKey;
        public Certificate AuthenticationCertificate { get; set; }


        public void Connect()
        {
#if SUPPORT_TLS_CWT
            if (CwtTrustKeySet != null) {
                _tlsSession = new TLSClient(null, _userKey, CwtTrustKeySet);

            }
            else {
#endif
                if (_userKey.PrivateKey.HasKeyType((int) COSE.GeneralValuesInt.KeyType_Octet)) {
                    CBORObject kid = _userKey.PrivateKey[COSE.CoseKeyKeys.KeyIdentifier];

                    BasicTlsPskIdentity pskIdentity = null;
                    if (kid != null) {
                        pskIdentity = new BasicTlsPskIdentity(kid.GetByteString(), _userKey.PrivateKey[CoseKeyParameterKeys.Octet_k].GetByteString());
                    }
                    else {
                        pskIdentity = new BasicTlsPskIdentity(new byte[0], _userKey.PrivateKey[CoseKeyParameterKeys.Octet_k].GetByteString());
                    }
                    _tlsSession = new TLSClient(null, pskIdentity);
                }
                else if (_userKey.PrivateKey.HasKeyType((int) COSE.GeneralValuesInt.KeyType_EC2)) {
                    _tlsSession = new TLSClient(null, _userKey);
                }
#if SUPPORT_TLS_CWT
            }
#endif
            _tlsSession.TlsEventHandler += OnTlsEvent;

            _authKey = _userKey.PrivateKey;

            TlsClientProtocol clientProtocol = new TlsClientProtocol(new SecureRandom());

            _tcpClient = new TcpClient(_ipEndPoint.AddressFamily);

            _tcpClient.Connect(_ipEndPoint);
            _tcpStream = _tcpClient.GetStream();

            clientProtocol.Connect(_tlsSession);

            while (_tlsSession.InHandshake) {
                bool sleep = true;
                int cbToRead = clientProtocol.GetAvailableOutputBytes();
                if (cbToRead != 0) {
                    byte[] data = new byte[cbToRead];
                    int cbRead = clientProtocol.ReadOutput(data, 0, cbToRead);
                    _tcpStream.Write(data, 0, cbRead);
                    sleep = false;
                }

                if (_tcpStream.DataAvailable) {
                    byte[] data = new byte[1024];
                    int cbRead = _tcpStream.Read(data, 0, data.Length);
                    Array.Resize(ref data, cbRead);
                    clientProtocol.OfferInput(data);
                    sleep = false;
                }

                if (sleep) Thread.Sleep(100);
            }

            _tlsClient = clientProtocol;

            //  Send over the capability block

            SendCSMSignal();

            //  

            if (_toSend != null) {
                _queue.Enqueue(_toSend);
                _toSend = null;
            }

            BeginRead();

            WriteData();
        }

        /// <summary>
        /// Start up a session on the server side
        /// </summary>
        public void Accept()
        {
            TlsServerProtocol serverProtocol = new TlsServerProtocol(new SecureRandom());

            TlsServer server = new TlsServer(_signingKeys, _clientKeys);

            //  Make sure we do not startup a listing thread as the correct call is always made
            //  byt the DTLS accept protocol.

            _tcpStream = _tcpClient.GetStream();
            server.TlsEventHandler += OnTlsEvent;
            serverProtocol.Accept(server);

            bool sleep = true;
            while (!server.HandshakeComplete) {
                sleep = true;
                
                if (_tcpStream.DataAvailable) {
                    byte[] data = new byte[1024];
                    int cbRead = _tcpStream.Read(data, 0, data.Length);
                    Array.Resize(ref data, cbRead);
                    serverProtocol.OfferInput(data);
                    sleep = false;
                }

                int cbToRead = serverProtocol.GetAvailableOutputBytes();
                if (cbToRead != 0) {
                    byte[] data = new byte[cbToRead];
                    int cbRead = serverProtocol.ReadOutput(data, 0, cbToRead);
                    _tcpStream.Write(data, 0, cbRead);
                    sleep = false;
                }


                if (sleep) Thread.Sleep(100);
            }

            _tlsServer = serverProtocol;
            _authKey = server.AuthenticationKey;
            AuthenticationCertificate = server.AuthenticationCertificate;
        }

        private void OnTlsEvent(object sender, TlsEvent tlsEvent)
        {
            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null)
            {
                handler(sender, tlsEvent);
            }
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
                int cbRead;
                byte[] buffer = new byte[1024];

                if (!_queue.TryDequeue(out q)) {
                    break;
                }

                if (_tlsClient != null) {
                    _tlsClient.OfferOutput(q.Data, 0, q.Data.Length);
                    do {
                        cbRead = _tlsClient.ReadOutput(buffer, 0, buffer.Length);

                        _tcpStream.Write(buffer, 0, cbRead);
                    } while (cbRead > 0);
                }
                else if (_tlsServer != null) {
                    _tlsServer.OfferOutput(q.Data, 0, q.Data.Length);
                    do {
                        cbRead = _tlsServer.ReadOutput(buffer, 0, buffer.Length);

                        _tcpStream.Write(buffer, 0, cbRead);
                    } while (cbRead > 0);

                }
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
                TLSSession session = (TLSSession) ar.AsyncState;

                int cbRead = session._tcpStream.EndRead(ar);
                session.ProcessInput(cbRead);
            }
            catch (System.IO.IOException) {
                ; // Ignore this error - but I don't know if that is correct.
            }
            catch (ObjectDisposedException) {
                ; // Ignore this error
            }
        }

        private byte[] _carryOver = null;
        private void ProcessInput(int cbRead)
        {
                byte[] data;

                byte[] result = new byte[cbRead];
                Array.Copy(_buffer, 0, result, 0, cbRead);

                if (_tlsClient != null) {
                    _tlsClient.OfferInput(result);

                    data = new byte[_tlsClient.GetAvailableInputBytes()];
                    _tlsClient.ReadInput(data, 0, data.Length);
                }
                else {
                    _tlsServer.OfferInput(result);

                    data = new byte[_tlsServer.GetAvailableInputBytes()];
                    _tlsServer.ReadInput(data, 0, data.Length);
                }

                if (data.Length == 0) {
                    BeginRead();
                    return;
                }

                byte[] bytes = new byte[(_carryOver != null ? _carryOver.Length : 0) + data.Length];
                if (_carryOver != null) {
                    Array.Copy(_carryOver, bytes, _carryOver.Length);
                    Array.Copy(data, 0, bytes, _carryOver.Length, cbRead);
                }
                else {
                    Array.Copy(data, bytes, data.Length);
                }

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
                        Array.Copy(bytes, message, messageSize);
                        Array.Copy(bytes, messageSize, bytes, 0, cbLeft - messageSize);
                        cbLeft -= messageSize;

                        FireDataReceived(message, EndPoint, null, this); // M00BUG
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

                BeginRead();
        }

        public event EventHandler<DataReceivedEventArgs> DataReceived;

        private void FireDataReceived(Byte[] data, System.Net.EndPoint ep, System.Net.EndPoint epLocal, TLSSession tcpSession)
        {
            EventHandler<DataReceivedEventArgs> h = DataReceived;
            if (h != null) {
                h(this, new DataReceivedEventArgs(data, ep, epLocal, tcpSession));
            }
        }

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

            WriteData();
        }
    }
}

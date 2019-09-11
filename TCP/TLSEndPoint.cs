using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.COSE;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Net;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// An implemention of a CoAP End Point that uses TLS as the underlying
    /// transport rather than UDP.  This endpoint class is designed for servers,
    /// for pure clients that are only doing requests they should use
    /// <cref target="TLSClientEndPoint"/>.
    /// </summary>
    public class TLSEndPoint : CoAPEndPoint
    {
        /// <inheritdoc/>
        public TLSEndPoint(TlsKeyPairSet signingKeys, KeySet clientKeys) : this(signingKeys, clientKeys, 0, CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TLSEndPoint(TlsKeyPairSet signingKeys, KeySet clientKeys, ICoapConfig config) : this(signingKeys, clientKeys, 0, config)
        {
        }

        /// <inheritdoc/>
        public TLSEndPoint(TlsKeyPairSet signingKeys, KeySet clientKeys, Int32 port) : this(new TLSChannel(signingKeys, clientKeys, port), CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TLSEndPoint(TlsKeyPairSet signingKeys, KeySet clientKeys, Int32 port, ICoapConfig config) : this (new TLSChannel(signingKeys, clientKeys, port), config)
        { }

        /// <inheritdoc/>
        public TLSEndPoint(TlsKeyPairSet signingKeys, KeySet clientKeys, System.Net.EndPoint localEP) : this(new TLSChannel(signingKeys, clientKeys, localEP), CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TLSEndPoint(TlsKeyPairSet signingKeys, KeySet clientKeys, System.Net.EndPoint localEP, ICoapConfig config) : this(new TLSChannel(signingKeys, clientKeys, localEP), config)
        {
        }

        /// <summary>
        /// Instantiates a new endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="channel"></param>
        /// <param name="config"></param>
        public TLSEndPoint(TLSChannel channel, ICoapConfig config) : base(channel, config)
        {
            Stack.Remove(Stack.Get("Reliability"));
            MessageEncoder = TlsCoapMesageEncoder;
            MessageDecoder = TlsCoapMessageDecoder;
        }


        static IMessageDecoder TlsCoapMessageDecoder(byte[] data)
        {
            return new TCPMessageDecoder(data);
        }

        static IMessageEncoder TlsCoapMesageEncoder()
        {
            return new TLSMessageEncoder();
        }

    }
}

using System;
using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.CoAP.Net;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// A CoAP End Point that uses TCP as the underlying transport rather than the
    /// default UDP.  This version is designed for servers, clients should use
    /// <cref target="TcpClientEndPoint"/> if they are only planning to do origination.
    /// </summary>
    public class TcpEndPoint : CoAPEndPoint
    {
        /// <inheritdoc/>
        public TcpEndPoint() : this(0, CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TcpEndPoint(ICoapConfig config) : this(0, config)
        {
        }

        /// <inheritdoc/>
        public TcpEndPoint(Int32 port) : this(new TCPChannel(port), CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TcpEndPoint(Int32 port, ICoapConfig config) : this (new TCPChannel(port), config)
        { }

        /// <inheritdoc/>
        public TcpEndPoint(System.Net.EndPoint localEP) : this(new TCPChannel(localEP), CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TcpEndPoint(System.Net.EndPoint localEP, ICoapConfig config) : this(new TCPChannel(localEP), config)
        {
        }

        /// <summary>
        /// Instantiates a new endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="channel"></param>
        /// <param name="config"></param>
        public TcpEndPoint(TCPChannel channel, ICoapConfig config) : base(channel, config)
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

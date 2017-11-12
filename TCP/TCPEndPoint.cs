using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.CoAP.Net;

namespace Com.AugustCellars.CoAP.TLS
{
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
        public TcpEndPoint(Int32 port) : this(new TcpChannel(port), CoapConfig.Default)
        {
        }

        public TcpEndPoint(Int32 port, ICoapConfig config) : this (new TcpChannel(port), config)
        { }

        /// <inheritdoc/>
        public TcpEndPoint(System.Net.EndPoint localEP) : this(new TcpChannel(localEP), CoapConfig.Default)
        {
        }

        /// <inheritdoc/>
        public TcpEndPoint(System.Net.EndPoint localEP, ICoapConfig config) : this(new TcpChannel(localEP), config)
        {
        }

        /// <summary>
        /// Instantiates a new endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="channel"></param>
        /// <param name="config"></param>
        public TcpEndPoint(TcpChannel channel, ICoapConfig config) : base(channel, config)
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

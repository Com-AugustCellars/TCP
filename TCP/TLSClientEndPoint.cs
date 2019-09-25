using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Client only version of a TLS end point.
    /// This end point will not accept new DTLS connections from other parities. 
    /// If this is needed then <see cref="TLSEndPoint"/> instead.
    /// </summary>
    public class TLSClientEndPoint : CoAPEndPoint
    {
        public EventHandler<TlsEvent> TlsEventHandler;

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific configuration
        /// </summary>
        /// <param name="config">Configuration info</param>
        /// <param name="tlsKey">Authentication information</param>
        public TLSClientEndPoint(OneKey tlsKey, ICoapConfig config) : this(tlsKey, 0, config)
        {
        }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific port
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="port">Client side port to use</param>
        public TLSClientEndPoint(OneKey tlsKey, int port = 0) : this(tlsKey, port, CoapConfig.Default)
        {
        }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="port">Client side port to use</param>
        /// <param name="config">Configuration info</param>
        public TLSClientEndPoint(OneKey tlsKey, int port, ICoapConfig config) : this(new TlsKeyPair(tlsKey), port, config)
        { }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="localEP">Client side endpoint to use</param>
        public TLSClientEndPoint(OneKey tlsKey, System.Net.EndPoint localEP) : this(tlsKey, localEP, CoapConfig.Default)
        {
        }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="localEP">Client side endpoint to use</param>
        /// <param name="config">Configuration info</param>
        public TLSClientEndPoint(OneKey tlsKey, System.Net.EndPoint localEP, ICoapConfig config) : this(new TlsKeyPair(tlsKey), localEP, config)
        {
        }

        public TLSClientEndPoint(TlsKeyPair userKey, int port=0) : this(userKey, port, CoapConfig.Default)
        {  }

        public TLSClientEndPoint(TlsKeyPair userKey, ICoapConfig config) : this (userKey, 0, config)
        {}

        public TLSClientEndPoint(TlsKeyPair userKey, int port, ICoapConfig config) : this(new TLSClientChannel(userKey, port), config)
        {
        }

        public TLSClientEndPoint(TlsKeyPair userKey, System.Net.EndPoint localEndPoint) : this(userKey, localEndPoint, CoapConfig.Default)
        { }

        public TLSClientEndPoint(TlsKeyPair userKey, System.Net.EndPoint localEndPoint, ICoapConfig config) : this(new TLSClientChannel(userKey, localEndPoint), config)
        { }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="channel">Channel interface to the transport</param>
        /// <param name="config">Configuration information for the transport</param>
        private TLSClientEndPoint(TLSClientChannel channel, ICoapConfig config) : base(channel, config)
        {
            Stack.Remove("Reliability");
            MessageEncoder = TcpCoapMesageEncoder;
            MessageDecoder = TcpCoapMessageDecoder;
            EndpointSchema = new[] {"coaps", "coaps+tcp"};
            channel.TlsEventHandler += OnTlsEvent;
        }

        /// <summary>
        /// Select the correct message decoder and turn the bytes into a message
        /// This is currently the same as the UDP decoder.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Interface to decoded message</returns>
        static IMessageDecoder UdpCoapMessageDecoder(byte[] data)
        {
            return new Spec.MessageDecoder18(data);
        }

        /// <summary>
        /// Select the correct message encoder and return it.
        /// This is currently the same as the UDP decoder.
        /// </summary>
        /// <returns>Message encoder</returns>
        static IMessageEncoder UdpCoapMesageEncoder()
        {
            return new Spec.MessageEncoder18();
        }


        static IMessageDecoder TcpCoapMessageDecoder(byte[] data)
        {
            return new TCPMessageDecoder(data);
        }

        static IMessageEncoder TcpCoapMesageEncoder()
        {
            return new TLSMessageEncoder();
        }
        private void OnTlsEvent(Object o, TlsEvent e)
        {
            EventHandler<TlsEvent> handler = TlsEventHandler;
            if (handler != null)
            {
                handler(o, e);
            }

        }

        public KeySet CwtTrustKeySet {
            get { return ((TLSClientChannel)_channel).CwtTrustKeySet; }
            set { ((TLSClientChannel)_channel).CwtTrustKeySet = value; }
        }
    }
}

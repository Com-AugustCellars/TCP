using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Client only version of a DTLS end point.
    /// This end point will not accept new DTLS connections from other parities. 
    /// If this is needed then <see cref="TLSEndPoint"/> instead.
    /// </summary>
    public class TLSClientEndPoint : CoAPEndPoint
    {
        private readonly OneKey _userKey;

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        public TLSClientEndPoint(OneKey tlsKey) : this(tlsKey, 0, CoapConfig.Default)
        {
        }

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
        public TLSClientEndPoint(OneKey tlsKey, Int32 port) : this(tlsKey, new TLSClientChannel(tlsKey, port), CoapConfig.Default)
        {
        }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="port">Client side port to use</param>
        /// <param name="config">Configuration info</param>
        public TLSClientEndPoint(OneKey tlsKey, Int32 port, ICoapConfig config) : this(tlsKey, new TLSClientChannel(tlsKey, port), config)
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
        public TLSClientEndPoint(OneKey tlsKey, System.Net.EndPoint localEP, ICoapConfig config) : this(tlsKey, new TLSClientChannel(tlsKey, localEP), config)
        {
        }

        /// <summary>
        /// Instantiates a new TCP endpoint with the specific channel and configuration
        /// </summary>
        /// <param name="tlsKey">Authentication information</param>
        /// <param name="channel">Channel interface to the transport</param>
        /// <param name="config">Configuration information for the transport</param>
        private TLSClientEndPoint(OneKey tlsKey, TLSClientChannel channel, ICoapConfig config) : base(channel, config)
        {
            Stack.Remove("Reliability");
            MessageEncoder = TcpCoapMesageEncoder;
            MessageDecoder = TcpCoapMessageDecoder;
            EndpointSchema = "coaps";
            _userKey = tlsKey;
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
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Net;
using Com.AugustCellars.CoAP.Codec;

namespace Com.AugustCellars.CoAP.TLS
{
    /// <summary>
    /// Client only version of a DTLS end point.
    /// This end point will not accept new DTLS connections from other parities. 
    /// If this is needed then <see cref="DTLSEndPoint"/> instead.
    /// </summary>
    public class TCPClientEndPoint : CoAPEndPoint
    {
            /// <summary>
            /// Instantiates a new TCP endpoint with the specific channel and configuration
            /// </summary>
            public TCPClientEndPoint() : this(0, CoapConfig.Default)
            {
            }

            /// <summary>
            /// Instantiates a new TCP endpoint with the specific configuration
            /// </summary>
            /// <param name="config">Configuration info</param>
            public TCPClientEndPoint(ICoapConfig config) : this(0, config)
            {
            }

            /// <summary>
            /// Instantiates a new TCP endpoint with the specific port
            /// </summary>
            /// <param name="port">Client side port to use</param>
            public TCPClientEndPoint(Int32 port) : this(new TCPClientChannel(port), CoapConfig.Default)
            {
            }

            /// <summary>
            /// Instantiates a new TCP endpoint with the specific channel and configuration
            /// </summary>
            /// <param name="port">Client side port to use</param>
            /// <param name="config">Configuration info</param>
            public TCPClientEndPoint(Int32 port, ICoapConfig config) : this(new TCPClientChannel(port), config)
            { }

            /// <summary>
            /// Instantiates a new TCP endpoint with the specific channel and configuration
            /// </summary>
            /// <param name="localEP">Client side endpoint to use</param>
            public TCPClientEndPoint(System.Net.EndPoint localEP) : this(localEP, CoapConfig.Default)
            {
            }

            /// <summary>
            /// Instantiates a new TCP endpoint with the specific channel and configuration
            /// </summary>
            /// <param name="localEP">Client side endpoint to use</param>
            /// <param name="config">Configuration info</param>
            public TCPClientEndPoint(System.Net.EndPoint localEP, ICoapConfig config) : this(new TCPClientChannel(localEP), config)
            {
            }

            /// <summary>
            /// Instantiates a new TCP endpoint with the specific channel and configuration
            /// </summary>
            /// <param name="channel">Channel interface to the transport</param>
            /// <param name="config">Configuration information for the transport</param>
            private TCPClientEndPoint(TCPClientChannel channel, ICoapConfig config) : base(channel, config)
            {
                Stack.Remove("Reliability");
                MessageEncoder = TcpCoapMesageEncoder;
                MessageDecoder = TcpCoapMessageDecoder;
                EndpointSchema = "coap";
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

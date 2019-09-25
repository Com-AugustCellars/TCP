using System.Text;
using Com.AugustCellars.CoAP.DTLS;
using Org.BouncyCastle.Crypto.Tls;

using Com.AugustCellars.COSE;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Com.AugustCellars.CoAP.TLS
{
    class TlsServer : DtlsServer
    {
        internal TlsServer(TlsKeyPairSet serverKeys, KeySet userKeys) : base(serverKeys, userKeys)
        {
        }

        protected override ProtocolVersion MinimumVersion => ProtocolVersion.TLSv10;
        protected override ProtocolVersion MaximumVersion => ProtocolVersion.TLSv12;

        public bool HandshakeComplete { get; private set; }
        public override void NotifyHandshakeComplete()
        {
            HandshakeComplete = true;
        }
    }
}

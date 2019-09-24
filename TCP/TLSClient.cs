using Com.AugustCellars.CoAP.DTLS;
#if SUPPORT_TLS_CWT
using Com.AugustCellars.WebToken;
#endif
using Org.BouncyCastle.Crypto.Tls;


namespace Com.AugustCellars.CoAP.TLS
{
    class TLSClient : DtlsClient
    {
        internal TLSClient(TlsSession session, TlsPskIdentity pskIdentity) : base(session, pskIdentity)
        {
        }

        internal TLSClient(TlsSession session, TlsKeyPair userKey) : base (session, userKey)
        {
        }

#if SUPPORT_TLS_CWT
        internal TLSClient(TlsSession session, TlsKeyPair tlsKey, KeySet cwtTrustKeys) : base(session, tlsKey, cwtTrustKeys)
        {
        }
#endif

        public override ProtocolVersion MinimumVersion => ProtocolVersion.TLSv10;

        public override ProtocolVersion ClientVersion => ProtocolVersion.TLSv12;

        public bool InHandshake { get; private set; } = true;
        public override void NotifyHandshakeComplete()
        {
            InHandshake = false;
        }
    }
}


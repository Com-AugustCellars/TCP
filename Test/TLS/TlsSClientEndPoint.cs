using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.COSE;
using PeterO.Cbor;

namespace Com.AugustCellars.CoAP.TLS
{
    [TestClass]
    public class TlsClientEndPointTest
    {
        private static OneKey PskOneKey;
#if SUPPORT_RPK
        private static OneKey RpkOneKey;
#endif

        [ClassInitialize]
        public static void OneTimeSetup(TestContext ctx)
        {
#if SUPPORT_RPK
            RpkOneKey = OneKey.GenerateKey(AlgorithmValues.ECDSA_256, GeneralValues.KeyType_EC, "P-256");
#endif

            PskOneKey = new OneKey();
            PskOneKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            PskOneKey.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(new byte[10]));
        }

        [TestMethod]
        public void TestNoKey()
        {
            try {
                TLSClientEndPoint ep =  new TLSClientEndPoint((TlsKeyPair) null);
                ep.Dispose();
                Assert.Fail("Should not have reached here.");
            }
            catch (ArgumentNullException e) {
                Assert.AreEqual(e.ParamName, "tlsKey");
            }
        }

#if SUPPORT_RPK
        [TestMethod]
        public void TestRpk()
        {
            TlsKeyPair tlsKey = new TlsKeyPair(RpkOneKey.PublicKey(), RpkOneKey);
            TLSClientEndPoint ep = new TLSClientEndPoint(RpkOneKey);
        }
#endif

        [TestMethod]
        public void NoEndPoint()
        {
            TLSClientEndPoint ep=  new TLSClientEndPoint(PskOneKey);
            Request req = new Request(Method.GET) {
                URI = new Uri("coaps+tcp://localhost:5682/.well-known/core"),
                EndPoint = ep
            };

            ep.Start();

            req.Send();
            req.WaitForResponse(5000);
        }

        [TestMethod]
        public void CoapURL()
        {
            TLSClientEndPoint ep = new TLSClientEndPoint(PskOneKey);
            Request req = new Request(Method.GET) {
                URI = new Uri("coap://localhost/.well-known/core"),
                EndPoint = ep
            };

            ep.Start();

            try {
                req.Send();
                req.WaitForResponse(5000);
            }
            catch (Exception e) {
                Assert.AreEqual(e.Message, "Schema is incorrect for the end point");
            }
        }
    }
}

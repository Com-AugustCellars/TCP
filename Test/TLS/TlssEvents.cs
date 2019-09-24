using System;
using System.Linq;
using System.Text;
using System.Threading;
using Com.AugustCellars.CoAP.DTLS;
using Com.AugustCellars.CoAP.Log;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.Server.Resources;
using Com.AugustCellars.CoAP.TLS;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using PeterO.Cbor;
using Uri = System.Uri;

namespace Com.AugustCellars.CoAP.TLS
{
    [TestClass]
    public class TlsEvents
    {
        private static OneKey PskOne;
        private static OneKey PskTwo;
        private static KeySet UserKeys;

        private CoapServer _server;
        private HelloResource _resource;
        private int _serverPort;

        private static readonly byte[] PskOneName = Encoding.UTF8.GetBytes("KeyOne");
        private static readonly byte[] PskTwoName = Encoding.UTF8.GetBytes("KeyTwo");

        [ClassInitialize]
        public static void OneTimeSetup(TestContext ctx)
        {
            PskOne = new OneKey();
            PskOne.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            PskOne.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(PskOneName));
            PskOne.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(Encoding.UTF8.GetBytes("abcDEFghiJKL")));

            PskTwo = new OneKey();
            PskTwo.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            PskTwo.Add(CoseKeyKeys.KeyIdentifier, CBORObject.FromObject(PskTwoName));
            PskTwo.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(Encoding.UTF8.GetBytes("12345678091234")));

            UserKeys = new KeySet();
            // UserKeys.AddKey(PskOne);
            // UserKeys.AddKey(PskTwo);
        }

        [TestInitialize]
        public void SetupServer()
        {
            Log.LogManager.Level = LogLevel.Fatal;
            CreateServer();
        }

        [TestCleanup]
        public void ShutdownServer()
        {
            _server.Dispose();
        }

        [TestMethod]
        public void TlsTestPskEvents()
        {
            Uri uri = new Uri($"coaps+tcp://localhost:{_serverPort}/Hello1");
            TLSClientEndPoint client = new TLSClientEndPoint(PskOne);
            client.Start();

            Request req = new Request(Method.GET) {
                URI = uri,
                EndPoint = client
            };

            req.Send();
            Response resp = req.WaitForResponse(50000);
            Assert.AreEqual(null, resp);
            client.Stop();

            TLSClientEndPoint client2 = new TLSClientEndPoint(PskTwo);
            client2.Start();
            Request req2 = new Request(Method.GET) {
                URI = uri,
                EndPoint = client2
            };

            req2.Send();
            string txt = req2.WaitForResponse(50000).ResponseText;
            Assert.AreEqual("Hello from KeyTwo", txt);

            client2.Stop();

            Thread.Sleep(5000);

        }


        private void CreateServer()
        {
            TLSEndPoint endpoint = new TLSEndPoint(null, UserKeys, 0);
            _resource = new HelloResource("Hello1");
            _server = new CoapServer();
            _server.Add(_resource);

            _server.AddEndPoint(endpoint);
            endpoint.TlsEventHandler += ServerEventHandler;
            _server.Start();
            _serverPort = ((System.Net.IPEndPoint)endpoint.LocalEndPoint).Port;
        }

        private static void ServerEventHandler(Object o, TlsEvent e)
        {
            switch (e.Code) {
                case TlsEvent.EventCode.UnknownPskName:
                    if (e.PskName.SequenceEqual(PskOneName)) {
                        //  We don't recognize this name
                    }
                    else if (e.PskName.SequenceEqual(PskTwoName)) {
                        e.KeyValue = PskTwo;
                   }
                    break;
            }
        }

        class HelloResource : Resource
        {
            public HelloResource(String name) : base(name)
            {

            }

            protected override void DoGet(CoapExchange exchange)
            {
                String content = $"Hello from ";

                content += Encoding.UTF8.GetString(exchange.Request.TlsContext.AuthenticationKey[CoseKeyKeys.KeyIdentifier].GetByteString());

                exchange.Respond(content);
            }
        }
    }
}

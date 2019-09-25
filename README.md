# TCP - Implementation of CoAP TCP connector in C#

[![NuGet Status](https://img.shields.io/nuget/v/Com.AugustCellars.CoAP.TCP.png)](https://www.nuget.org/packages/Com.AugustCellars.CoAP.TCP)
[![Build Status](https://api.travis-ci.org/Com.AugustCellars/TCP.bpng)](https://travis-ci.org/Com.AugustCelalrs/TCP)
[![Appveyor Build](https://ci.appveyor.com/api/projects/status/github/Com-AugustCellars/TCP?svg=true)](https://ci.appveyor.com/project/jimsch/coap-csharp)
[![CircleCI](https://circleci.com/gh/Com-AugustCellars/TCP.svg?style=svg)](https://circleci.com/gh/Com-AugustCellars/TCP)

The Constrained Application Protocol (CoAP) (https://datatracker.ietf.org/doc/draft-ietf-core-coap/)
is a RESTful web transfer protocol for resource-constrained networks and nodes.
CoAP.NET is an implementation in C# providing CoAP-based services to .NET applications.

The base specification uses UDP as the transport for sending messages.  [CoAP-TCP](https://datatracker.ietf.org/doc/draft-ietf-core-coap-tcp-tls/) provides a definition of how to use TCP with or without TLS as a transport protocol.  The use of TLS allows for reliable transport which can be advantagous in some circumstances, although with a corresponding increase in the code footprint and network traffic.

This project provides an implementation of the TCP and TLS connectors that can be used with the [CoAP.NET implementation](https://www.nuget.org/packages/Com.AugustCellars.CoAP).

Reviews and suggestions would be appreciated.

## Copyright

Copyright (c) 2017-9, Jim Schaad <ietf@augustcellars.com>

## Content

- [Quick Start](#quick-start)
- [Build](#build)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## How to Install

The C# implementation is available in the NuGet Package Gallery under the name [Com.AugustCellars.CoAP.TLS](https://www.nuget.org/packages/Com.AugustCellars.CoAP.TLS).
To install this library as a NuGet package, enter 'Install-Package Com.AugustCellars.CoAP.TLS' in the NuGet Package Manager Console.

## Documentation

Documentation can be found in two places.
First an XML file is installed as part of the package for inline documentation.
At some point, the [Wiki](https://github.com/jimsch/CoAP-CSharp/wiki) associated with this project.

## Quick Start

### CoAP Client

To use the TCP or TLS endpoint from a client, one starts by creating and starting the desired endpoint and then associating it with a request.  The same endpoint can be used with multiple requests and target addresses.

```csharp
  // Create the endpoint
  CoapEndpoint ep = new TcpEndpoint();
  ep.Start();

  Request request = new Request(Method.GET);
  request.URI = new Uri("coap://[::1]/hello-world");
  request.EndPoint = ep;
  request.Send();

  //  Wait for one response
  Response response = request.WaitForResponse();
```

The endpoint MUST be started before it can be used, this is not done automatically.  The endpoint SHOULD be stopped before it is disposed of, but that will happen eventially even if it is not marked as such.  However the TCP connection will not be closed until the endpoint is stopped.


### CoAP Server

A TCP endpoint is added to a CoAP server object in a similar manner.  As long as the endpoint is added to the server before it is started, then starting the endpoint is optional.  Similarly the endpoint will be shutdown when the server is stopped.

## Building the sources

I am currently sync-ed up to Visual Studio 2019 and have started using language features of C# v7.0 that are supported both in Visual Studio and in the latest version of mono.

## License

See [LICENSE](LICENSE) for more info.


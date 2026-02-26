# XAdES

## Table of Contents <!-- omit in toc -->

- [Overview](#overview)
- [Generate Codes from XML schema](#generate-codes-from-xml-schema)

## Overview

For more information,

- [XML Advanced Electronic Signatures (XAdES) - W3C](https://www.w3.org/TR/XAdES/)

## Generate Codes from XML schema

The package provides Xml wrapper classes related to SignedXml, but does not provide classes related to XAdES.
However, having wrapper classes would make implementation easier.

I downloaded the XAdES schema file from the link below and ran `dotnet-xscgen` to create the classes.

- <https://uri.etsi.org/01903/v1.4.1/>

[XmlSampleGenerator.Build.targets](./XmlSampleGenerator.Build.targets) for information on how to generate it.

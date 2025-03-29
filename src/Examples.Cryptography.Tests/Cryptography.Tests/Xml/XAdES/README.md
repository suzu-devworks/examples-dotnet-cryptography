# XAdES

## Table of Contents <!-- omit in toc -->

- [XAdES](#xades)
  - [Overview](#overview)
  - [Test Codes](#test-codes)
  - [Generate Codes](#generate-codes)

## Overview

For more information, [here ...](https://www.w3.org/TR/XAdES/)

## Test Codes

[See ...](./)

## Generate Codes

The package provides Xml wrapper classes related to SignedXml, but does not provide classes related to XAdES.
However, having wrapper classes would make implementation easier.

I downloaded the XAdES schema file from the link below and ran `dotnet-xscgen` to create the classes.

- <https://uri.etsi.org/01903/v1.4.1/>

[XmlSampleGenerator.Build.targets](./XmlSampleGenerator.Build.targets) for information on how to generate it.

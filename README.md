# Stateless DANE
Based on [letsdane](https://github.com/buffrr/letsdane/).

This repository contains code for proof-of-concept client implementation of [stateless DANE](https://github.com/handshake-org/HIPs/blob/master/HIP-0017.md).

Server part can be found here: https://github.com/htools-org/stateless-dane. 

# How it works

Similar to letsdane, it setups a proxy server which listens for incoming connections, resolves the hostname, checks if the provided certificate
is correct and then outputs a self-signed certificate. Therefore the browser must have added a new certificate authority.

Internally it uses hnsd to sync tree roots. The initial syncronization might take several minutes. Afterwards, using
checkpoint, hnsd has to syncrhonize last ~2k roots which usually takes 5 seconds.

hnsd default port is `5350`

## Install

In order to use SANE it's needed to have installed [hnsd fork](https://github.com/randomlogin/hnsd), next it's needed to
provide path to the executable either via flag or via environment variable `export HNSD_PATH="~/hnsd/hnsd"`.

Default directory containing CA files and saved tree roots is `~/.sane/`.

## DNSSEC

DNSSEC verification is done in the following way:

1. Records from the extension are read, abort if there are any records except: TLSA, RRSIG, DNSKEY, DS.
2. The records are linearly sorted by 'subdomain' relation. Abort if cannot be done.
3. The only TLSA record is found, abort is there are several of them.
4. The chain TLSA -> RRSIG -> DS & DNSKEY chain up to the root zone is checked, abort if there is an error.

## Build from source

You can build the latest version from source for now. binaries in releases are not up to date yet.

Go 1.21+ is required. 

```
git clone https://github.com/randomlogin/sane.git && cd sane/cmd/sane
go build 
```

## Quick Usage

SANE will generate a CA and store it in `~/.sane` when you start it for the first time.
It's needed to specify path to `hnsd` to run SANE.
Your resolver should be able to resolve handshake domains.
To start the proxy server :
```
export HNSD_PATH="~/hnsd/hnsd"
./sane
```

Using local Handshake hnsd resolver would result in an error, as it will try to run the second instance of hnsd.


- Add SANE proxy to your web browser `127.0.0.1:8080` ([Firefox example](https://user-images.githubusercontent.com/41967894/117558156-8f5b2a00-b02f-11eb-98ba-91ce8a9bdd4a.png))

- Import the certificate file into your browser certificate store ([Firefox example](https://user-images.githubusercontent.com/41967894/117558164-a7cb4480-b02f-11eb-93ed-678f81f25f2e.png)).


## Example website

https://collate/ has a certificate complying to the HIP17.

## Known problems

1. Rejects websites without HIP17 certificates instead of passing their certificates.
2. Time intervals and UPDATEs are not handled properly.
3. Several TLSA records are not supported yet.

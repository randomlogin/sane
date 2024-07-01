# Stateless DANE
This repository contains code for proof-of-concept client implementation of [stateless DANE](https://github.com/handshake-org/HIPs/blob/master/HIP-0017.md).\
Server part can be found here: https://github.com/htools-org/stateless-dane. \
Based on [letsdane](https://github.com/buffrr/letsdane/).

## How it works

Similar to letsdane, it sets up a proxy server which listens for incoming connections, resolves the hostname, checks if the provided certificate
is correct and then outputs a self-signed certificate (signed by local certificate authority which has to be added to the browser's trusted ones).

### hnsd 
Internally it uses hnsd to sync tree roots. The initial syncronization might take several minutes. Afterwards, using
checkpoints, hnsd has to syncrhonize last ~2k roots which usually takes 5 seconds. After synchronization, hnsd is
terminated.

Internal hnsd daemon has `5350` as a default port.

## Install

Dependencies:
```
apt-get install libgetdns-dev
```

Actual build

```
git clone https://github.com/randomlogin/sane.git && cd sane/cmd/sane
go build 
```

Next, in order to use SANE it's needed to have [hnsd](https://github.com/handshake-org/hnsd) installed. 
One can provide the path to the `hnsd` executable either via flag `-hnsd` or via environment variable 

`export HNSD_PATH="~/hnsd/hnsd"`

Default directory containing CA files and saved tree roots is `~/.sane/`.

## Usage

SANE will generate a certificate authority and store it in `~/.sane` when you start it for the first time.\
To start SANE using handshake DNS Over HTTPS resolver:

```
export HNSD_PATH="~/hnsd/hnsd"
./sane -r https://hnsdoh.com
```

An additional parameter can be added: the external server which provides both DNSSEC and urkel proof for the domain,
which allows to browse websites without SANE-compliant certificates (of course this external service must be trusted).

```
./sane -r https://hnsdoh.com -external-service https://sdaneproofs.htools.work/proofs/
```

Additional arguments can be viewed by invoking help:
```
./sane --help
```

### Urkel tree
SANE looks for an extension in the certificate which contains an urkel tree proof, verifies it, checks if the root is not
older than a week.\
Native [golang implementation of urkel tree](https://github.com/nodech/go-hsd-utils/) is used.

### DNSSEC
Another extension from the certificate contains DNSSEC verifiation chain. Its verification is done locally using
[getdns](https://getdnsapi.net/), it does not call any resolvers.


### Browser settings
- Add SANE proxy to your web browser `127.0.0.1:8080` ([Firefox example](https://user-images.githubusercontent.com/41967894/117558156-8f5b2a00-b02f-11eb-98ba-91ce8a9bdd4a.png))
- Import the certificate file into your browser certificate store ([Firefox example](https://user-images.githubusercontent.com/41967894/117558164-a7cb4480-b02f-11eb-93ed-678f81f25f2e.png)).

### Requirements
Go 1.21+ is required. \
hnsd 2.99.0+ is required.

### Example websites

Following websites provide examples of websites compliant with SANE (including wildcard certificates):
- [htools/](https://htools/) 
- [test.lazydane/](https://test.lazydane/) 

## Debug

Default output log provides sufficient information about what is happening, though additional `--verbose` flag might
help to locate the exact code locations where the logging comes from. 

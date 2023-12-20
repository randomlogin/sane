# Stateless DANE
Based on [letsdane](https://github.com/buffrr/letsdane/).

This repository contains code for proof-of-concept implementation of [stateless DANE](https://github.com/handshake-org/HIPs/blob/master/HIP-0017.md) clients.
Current version searches for certificate extension which contains urkel proof and ignores the DNSSEC part.

Server part can be found here: https://github.com/htools-org/stateless-dane. 

# How it works

Similar to letsdane, it setups a proxy server which listens for incoming connections, resolves the hostname, checks if the provided certificate
is correct and then outputs a self-signed certificate. Therefore the browser must have added a new certificate
authority.

Internally it uses hnsd to sync tree roots.

## Install

In order to use SANE it's needed to have installed [hnsd fork](https://github.com/randomlogin/hnsd), next it's needed to
provide path to the executable either via flag or via environment variable `export HNSD_PATH="~/hnsd/hnsd"`.

Default directory containing CA files and saved tree roots is `~/.sane/`.


## Build from source

You can build the latest version from source for now. binaries in releases are not up to date yet.

Go 1.21+ is required. (unbound is optional omit `-tags unbound` to use AD bit only)

```
apt install libunbound-dev
git clone https://github.com/randomlogin/sane.git && cd sane/cmd/sane
go build -tags unbound
```

## Quick Usage

SANE will generate a CA and store it in `~/.sane` when you start it for the first time.
To start the proxy server:
```
export HNSD_PATH="~/hnsd/hnsd"
./sane -r https://easyhandshake.com:8053 -skip-dnssec
```

Using local Handshake hnsd resolver would result in an error, as it will try to run the second instance of hnsd.


- Add SANE proxy to your web browser `127.0.0.1:8080` ([Firefox example](https://user-images.githubusercontent.com/41967894/117558156-8f5b2a00-b02f-11eb-98ba-91ce8a9bdd4a.png))

- Import the certificate file into your browser certificate store ([Firefox example](https://user-images.githubusercontent.com/41967894/117558164-a7cb4480-b02f-11eb-93ed-678f81f25f2e.png)).


## Example website

https://collate/ has a certificate complying to the HIP17.


## Known problems

1. Rejects websites without HIP17 certificates instead of passing their certificates.
2. Doesn't check DNSSEC extension.
3. Time intervals and UPDATEs are not handled properly.



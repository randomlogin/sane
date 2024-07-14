#Build hnsd
FROM alpine AS build-hnsd

RUN apk add --no-cache \
  build-base \
  bash \
  automake \
  autoconf \
  libtool \
  unbound-dev \
  git

WORKDIR /hnsd
RUN git clone https://github.com/handshake-org/hnsd.git .
RUN ./autogen.sh && ./configure && make

#Build sane
FROM golang:1.21-alpine AS build-sane
WORKDIR /sane
COPY . /sane

RUN echo "@edge-testing http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN apk add --no-cache getdns-dev@edge-testing git gcc musl-dev

RUN go mod tidy
RUN CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib -lgetdns" CGO_CFLAGS="-I/usr/include" go build -o sane cmd/sane/main.go 

FROM alpine
RUN echo "@edge-testing http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN apk update && apk add --no-cache getdns@edge-testing

COPY --from=build-hnsd /hnsd/hnsd /usr/local/bin/hnsd
COPY --from=build-sane /sane/sane /usr/local/bin/sane

ENV HNSD_PATH /usr/local/bin/hnsd

EXPOSE 9590

ENTRYPOINT ["/usr/local/bin/sane"]
CMD ["-r", "https://hnsdoh.com", "-external-service", "https://sdaneproofs.htools.work/proofs/", "--verbose", "-addr", "0.0.0.0:9590"]

FROM nvidia/cuda:11.4.1-devel-ubuntu20.04
MAINTAINER Marcus Dansarie <marcus@dansarie.se>

WORKDIR /usr/src/socracked

COPY . .

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get -y full-upgrade \
  && apt-get -y install cmake libmsgpack-dev libncurses-dev \
  && rm -rf build\
  && mkdir build \
  && cd build \
  && cmake .. \
  && make \
  && make install

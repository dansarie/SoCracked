FROM nvidia/cuda:11.4.1-devel-ubuntu20.04
MAINTAINER Marcus Dansarie <marcus@dansarie.se>

WORKDIR /work

COPY . /usr/src/socracked

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get -y full-upgrade \
  && apt-get -y install cmake libncurses-dev libxml2-dev \
  && cd /usr/src/socracked \
  && rm -rf build\
  && mkdir build \
  && cd build \
  && cmake .. \
  && make \
  && make install

FROM ubuntu:xenial
RUN mkdir /deb
RUN apt-get -qq update && apt-get -qq upgrade && apt-get install -y git devscripts equivs
COPY debian/control /python-fido-host/debian/control
RUN yes | mk-build-deps -i /python-fido-host/debian/control

COPY . /python-fido-host
RUN cd /python-fido-host && debuild -us -uc

RUN mv /python-fido-host_* /python3-fido-host_* /deb
RUN tar czf /python-fido-host-debian-packages.tar.gz /deb

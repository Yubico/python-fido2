FROM ubuntu:xenial
RUN mkdir /deb
RUN apt-get -qq update && apt-get -qq upgrade && apt-get install -y git devscripts equivs
COPY debian/control /python-fido2/debian/control
RUN yes | mk-build-deps -i /python-fido2/debian/control

COPY . /python-fido2
RUN cd /python-fido2 && debuild -us -uc

RUN mv /python-fido2_* /python3-fido2_* /deb
RUN tar czf /python-fido2-debian-packages.tar.gz /deb

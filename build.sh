# Copyright (c) Authors of Clover
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0

GOVERSION=1.13
OS=linux
ARCH=amd64
GOPATH=/home/s3wong/go

SRCDIR=`pwd`

#wget https://dl.google.com/go/go$GOVERSION.$OS-$ARCH.tar.gz
#sudo tar -C /usr/local -xzf go$GOVERSION.$OS-$ARCH.tar.gz
#export PATH=$PATH:/usr/local/go/bin
#export PATH=$GOPATH/bin:$PATH

#sudo apt install -y gcc
#sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD
#echo "deb https://repo.iovisor.org/apt/bionic bionic main" | sudo tee /etc/apt/sources.list.d/iovisor.list
#sudo apt-get update -y
#sudo apt-get install -y bcc-tools libbcc-examples linux-headers-$(uname -r)

/usr/local/go/bin/go get github.com/google/gopacket
/usr/local/go/bin/go get github.com/iovisor/gobpf
/usr/local/go/bin/go get github.com/opentracing/opentracing-go
/usr/local/go/bin/go get github.com/pkg/errors
/usr/local/go/bin/go get github.com/go-redis/redis
/usr/local/go/bin/go get github.com/uber/jaeger-client-go
/usr/local/go/bin/go get github.com/vishvananda/netlink
/usr/local/go/bin/go get github.com/vishvananda/netns
/usr/local/go/bin/go get golang.org/x/sys/unix
#cd $GOPATH/src/golang.org/x/sys/unix
#git checkout $GOLANGUNIXVERSION

/usr/local/go/bin/go get github.com/tools/godep
/usr/local/go/bin/go get k8s.io/client-go/...
#cd $GOPATH/src/k8s.io/client-go
#git checkout $CLIENTGOVERSION
#godep restore ./...

#cd $SRCDIR/libclovisor
#go build .
#cd ../
#go build -o clovisor .

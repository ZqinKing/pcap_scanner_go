# ---- Stage 1: Build on CentOS 7 ----
FROM quay.io/centos/centos:7 AS builder

# Solve CentOS 7 EOL repository issues and install build dependencies
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org/centos/$releasever/os/$basearch/|baseurl=http://vault.centos.org/7.9.2009/os/$basearch/|g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org/centos/$releasever/updates/$basearch/|baseurl=http://vault.centos.org/7.9.2009/updates/$basearch/|g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org/centos/$releasever/extras/$basearch/|baseurl=http://vault.centos.org/7.9.2009/extras/$basearch/|g' /etc/yum.repos.d/CentOS-Base.repo && \
    yum update -y && \
    yum install -y libpcap-devel gcc wget tar && \
    yum clean all

# Install Go 1.23
ENV GOLANG_VERSION=1.23.2
RUN wget https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG BUILD_VERSION
# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -v -o pcap_scanner -ldflags="-s -w -X 'main.version=${BUILD_VERSION}'" -tags 'netgo osusergo' ./src

# ---- Stage 2: Final ----
FROM quay.io/centos/centos:7

WORKDIR /app

# Solve CentOS 7 EOL repository issues
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org/centos/$releasever/os/$basearch/|baseurl=http://vault.centos.org/7.9.2009/os/$basearch/|g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org/centos/$releasever/updates/$basearch/|baseurl=http://vault.centos.org/7.9.2009/updates/$basearch/|g' /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i 's|#baseurl=http://mirror.centos.org/centos/$releasever/extras/$basearch/|baseurl=http://vault.centos.org/7.9.2009/extras/$basearch/|g' /etc/yum.repos.d/CentOS-Base.repo

# Install runtime dependency libpcap
RUN yum update -y && \
    yum install -y libpcap && \
    yum clean all

COPY --from=builder /app/pcap_scanner .

CMD ["./pcap_scanner"]

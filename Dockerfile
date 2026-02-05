FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        inetutils-ping \
        iproute2 \
        man-db \
        manpages \
        make \
        traceroute \
        strace && \
    rm -rf /var/lib/apt/lists/*

# Copie SEULEMENT le code source (pas les binaires)
COPY . /src
WORKDIR /src

# Nettoie puis compile dans le container
RUN make clean && make

CMD ["/bin/bash"]

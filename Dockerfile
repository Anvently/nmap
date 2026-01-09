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

# Copie ton code source dans le container
# (si ton ft_ping est un fichier unique, adapte selon ton projet)
COPY . /src

WORKDIR /src

RUN make

CMD ["/bin/bash"]

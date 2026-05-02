
FROM devkitpro/devkitppc:20260221@sha256:db8e39c73546d461d5606dc7dfed462a7d5957498502562e3b46769d02496cc1 AS builder

ADD --chmod=0755 --checksum=sha256:c125df9762b0c7233459087bb840c0e5dbfc4d9690ee227f1ed8994f4d51d2e0 \
    https://raw.githubusercontent.com/reproducible-containers/repro-sources-list.sh/v0.1.4/repro-sources-list.sh \
    /usr/local/bin/repro-sources-list.sh

RUN \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    /usr/local/bin/repro-sources-list.sh && \
    apt-get update && \
    apt-get install -y python3-pip

# We need pycryptodome for the create_binary_blob.py script
RUN pip3 install --break-system-packages pycryptodome==3.23.0

# Clone a fork of wut with compute shader support. Note: eventually, the pull
# request will probably be merged after which this fork might disappear.
# 
# PR: https://github.com/devkitPro/wut/pull/437
WORKDIR /builder
RUN git clone https://github.com/MaxNiftyNine/wut.git

WORKDIR /builder/wut
RUN git checkout 81ffe74c6902b313fd73d21852ea58449a90544e
RUN rm -rf .git
RUN make
RUN make install

# Clone the rio game framework
WORKDIR /builder
RUN git clone https://github.com/aboood40091/rio

WORKDIR /builder/rio
RUN git checkout 14eda392390837bf2ad3b5e40eb0a89df6fe94d8
RUN rm -rf .git

# Now we build the game
# 
# Note: the working directory cannot be /build, because the Makefile has
# different behavior when it is invoked from a directory called 'build'.
WORKDIR /builder
COPY challenge .

RUN python3 create_binary_blob.py
RUN make

RUN wuhbtool fs/code/challenge.rpx challenge.wuhb --content=fs/content

FROM scratch
COPY --from=builder /builder/challenge.wuhb /

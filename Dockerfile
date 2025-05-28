FROM debian:bookworm-slim AS build

WORKDIR /app
COPY . /app
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && apt-get -y --no-install-recommends install ca-certificates git make cmake gcc libssl-dev openssl build-essential autoconf-archive libcmocka0 libcmocka-dev procps iproute2 pkg-config automake uthash-dev autoconf doxygen libjson-c-dev libini-config-dev libcurl4-openssl-dev uuid-dev libltdl-dev libusb-1.0-0-dev libftdi-dev libtool mosquitto\ 
    tpm2-tools libtss2-dev\
    && rm -rf /var/lib/apt/lists/*

#RUN git submodule update --init --recursive && cd lib/tpm2-tools && git checkout 4998ecfea817cd0efdd47bdf11a02dedab51c723 && cd ../../
RUN cp patches/tpm2-tools/config.h lib/tpm2-tools/lib/config.h
RUN cat ./scripts/create_hash_dir.sh 
RUN /app/scripts/create_hash_dir.sh ./
RUN mkdir build && cmake -B build . 
RUN cd build  && make join_service && make verifier
WORKDIR /app/build

FROM debian:bookworm-slim
WORKDIR /app
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update \
    && apt-get -y --no-install-recommends install ca-certificates libssl-dev openssl iproute2 libjson-c-dev libini-config-dev libcurl4-openssl-dev uuid-dev libltdl-dev libusb-1.0-0-dev libftdi-dev libtool mosquitto\ 
    tpm2-tools libtss2-dev\
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/build/join_service.build/join_service /app/join_service.build/join_service
COPY --from=build /app/build/verifier.build/verifier /app/verifier.build/verifier
COPY --from=build /app/tpm_ca_certs_hash_dir  /app/tpm_ca_certs_hash_dir
COPY --from=build /app/mosquitto.conf  /app/mosquitto.conf
COPY --from=build /app/join_service.sh /app/join_service.sh
COPY --from=build /app/verifier.sh /app/verifier.sh
RUN mkdir -p /var/embrave/verifier/whitelist/
COPY --from=build /app/goldenvalues.db //var/embrave/verifier/whitelist/goldenvalues.db

ENTRYPOINT []
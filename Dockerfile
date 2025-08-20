# syntax=docker/dockerfile:1

FROM scratch

WORKDIR /

# Piper adds a platform name suffix, so we have to include "-linux-amd64" in a output directory.
COPY bin-linux-amd64/aws bin/aws

CMD ["ls -lrt"]


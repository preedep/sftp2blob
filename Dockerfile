# Stage 1: Build Stage
FROM alpine:3.18 AS build-stage

# Install necessary build packages and clean up afterwards
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    linux-headers \
    python3-dev \
    py3-pip \
    py3-virtualenv \
    curl \
    jq \
    && python3 -m venv /opt/venv \
    && . /opt/venv/bin/activate \
    && pip install --upgrade pip \
    && pip install azure-cli \
    && curl -L https://aka.ms/downloadazcopy-v10-linux | tar -xz -C /tmp \
    && apk del .build-deps

# Stage 2: Runtime Stage
FROM alpine:3.18

# Install runtime dependencies only
RUN apk add --no-cache \
    bash \
    openssh-client \
    lftp \
    ca-certificates \
    libc6-compat \
    jq

# Copy the virtual environment from the build stage
COPY --from=build-stage /opt/venv /opt/venv

# Copy azcopy from the build stage
COPY --from=build-stage /tmp/azcopy_linux_amd64_*/azcopy /usr/bin/

# Copy the shell script into the container
COPY sftp2blob.sh /usr/local/bin/sftp2blob.sh

# Make the azcopy and script executable
RUN chmod +x /usr/bin/azcopy && chmod +x /usr/local/bin/sftp2blob.sh

# Ensure the virtual environment is in the PATH
ENV PATH="/opt/venv/bin:$PATH"

# Set the default command to execute the script
ENTRYPOINT ["/usr/local/bin/sftp2blob.sh"]
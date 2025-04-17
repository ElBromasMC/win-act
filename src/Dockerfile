FROM python:3.12-alpine AS base

# Install run-time and compile-time system dependencies
USER root
RUN apk add --no-cache \
    bash

# Create and switch to non-root user
RUN addgroup -g 1000 runner \
    && adduser -G runner -u 1000 -D runner
USER runner

# Install run-time and compile-time local dependencies

# Create required folders and change to source directory
RUN mkdir -p \
    /home/runner/src \
    /home/runner/data
VOLUME /home/runner/data
WORKDIR /home/runner/src

# Install run-time and compile-time project dependencies
RUN python -m venv venv \
    && . venv/bin/activate \
    && pip install \
    Flask \
    pytz

#
# Production
#

FROM base AS production

# Copy source files
USER runner
WORKDIR /home/runner/src
COPY --chown=runner:runner . .

# Expose required ports
EXPOSE 5000

# Define entrypoint
COPY --chown=runner:runner ./scripts/entrypoint-prod.sh /home/runner/
ENTRYPOINT ["/home/runner/entrypoint-prod.sh"]

#
# Development
#

FROM base AS development

# Install dev-time system dependencies

# Change to non-root user
USER runner

# Install dev-time local dependencies

# Create required folders and change to source directory
WORKDIR /home/runner/src

# Install dev-time project dependencies

# Move temporally project dependencies and clean source directory
RUN mv venv ../

# Expose required ports
EXPOSE 5000

# Define entrypoint
COPY --chown=runner:runner ./scripts/entrypoint-dev.sh /home/runner/
ENTRYPOINT ["/home/runner/entrypoint-dev.sh"]


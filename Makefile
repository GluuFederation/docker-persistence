.DEFAULT_GOAL := build-dev

GLUU_VERSION=4.0.1
IMAGE_NAME=gluufederation/persistence
UNSTABLE_VERSION=dev
RHEL_VERSION=rhel

build-dev:
	@echo "[I] Building Docker image ${IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}"
	@docker build --rm --force-rm -t ${IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} .

build-dev-rhel:
	@echo "[I] Building Docker image ${IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}_${RHEL_VERSION}"
	@docker build --rm --force-rm -t ${IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}_${RHEL_VERSION} -f Dockerfile.rhel .

.PHONY: build push check-env

build:
	@echo "Building image..."
	./scripts/build_image.sh

check-env:
ifndef HOST_IP
	$(error HOST_IP is undefined)
endif
ifndef SSH_KEY
	$(error SSH_KEY is undefined)
endif
ifndef PORT
	$(error PORT is undefined)
endif

push: check-env build
	@echo "Deploying to host $(HOST_IP)..."
	./scripts/deploy_image_to_host.sh $(HOST_IP) $(SSH_KEY) $(PORT)

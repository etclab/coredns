.PHONY: build sign run clean sim

# Build the enclave binary (requires ego-go)
build:
	cd cmd && ego-go build -o ../enclave .

# Generate signing key and sign the enclave
sign: build
	@if [ ! -f private.pem ]; then \
		openssl genrsa -out private.pem 3072; \
	fi
	ego sign enclave

# Run in SGX hardware mode
run: sign
	ego run enclave

# Run in simulation mode (no SGX hardware required)
sim: build
	OE_SIMULATION=1 ego run enclave

# Build and run without SGX (for development on non-SGX machines)
dev:
	cd cmd && go build -o ../enclave-dev .
	./enclave-dev

clean:
	rm -f enclave enclave-dev private.pem public.pem

all:
		cd daemon && make
		cd cli && cargo build --release

install:
		cp ./daemon/fprocd /usr/local/bin
		cp ./cli/target/release/dyspro-cli /usr/local/bin
		strip /usr/local/bin/dyspro-cli

clean:
		rm -rf ./damon/fprocd
		rm -rf ./cli/target
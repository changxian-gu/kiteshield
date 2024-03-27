all:
	make -C crypto clean
	make -C crypto lib
	cp crypto/libcrypto.a ../cyclone_cipher/
	make -C ecc_demo clean
	make -C ecc_demo lib
	cp ecc_demo/libecc.a ../cyclone_cipher/
	make -C zstd/lib clean
	make -C zstd/lib libzstd.a
	cp zstd/lib/libzstd.a ../compression/zstd/
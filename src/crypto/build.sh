#!/usr/bin/env bash

SSEFLAGS="-march=native -mno-avx512f -O3"

INCLUDE="-Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include"

export NIX_ENFORCE_NO_NATIVE=0

CC=gcc

declare -a FILES=("crypto.c"
	   "hacl/Hacl_Curve25519_51.c"
	   "hacl/Hacl_Hash_SHA3.c"
	   "hacl/Hacl_NaCl.c"
	   "hacl/Hacl_Salsa20.c"
	   "hacl/Hacl_MAC_Poly1305.c"
	   "hacl/Hacl_Hash_SHA2.c"
	   #For signing of report
	   "hacl/Hacl_Ed25519.c"
	  )


comp() {
	for f in "${FILES[@]}"
	do
		$CC $SSEFLAGS $INCLUDE -nostdlib -fPIC -c $f -o $f.o 2>&1
		echo "$CC $SSEFLAGS $INCLUDE -nostdlib -fPIC -c $f -o $f.o"
	done
}

RES=1
while (( $RES != 0 )); do
	comp
	echo "ar rcs libhaclcrypto.a ${FILES[@]/%/.o}"
	ar rcs libhaclcrypto.a "${FILES[@]/%/.o}"
	RES=$?
done

RES=$(rm "${FILES[@]/%/.o}")
exit 0

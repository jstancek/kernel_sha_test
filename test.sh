#!/bin/bash

TESTFILE="random"
total=0

trap ctrl_c INT

function ctrl_c()
{
	rmmod sha_hash_test
}

function test_size()
{
	local size=$1
	local hashname=$2
	local uhashcmd=$3
	local chunksize=$4
	local offset=$5

	total=$((total + 1))
	echo "$hashname $size $chunksize $offset" > /proc/sha_test
	local ksum=$(cat /proc/sha_test)

	local hbytes=$((size + offset))
	local usum=$(head -c $hbytes $TESTFILE | tail -c $size | $uhashcmd | awk '{print $1}')

	if [ "$ksum" == "$usum" ]; then
		echo "PASS $total, hash:$hashname size:$size chunk:$chunksize off:$offset"
	else
		echo "FAIL $total, hash:$hashname size:$size chunk:$chunksize off:$offset"
		echo "ksum: $ksum"
		echo "usum: $usum"
		exit 1
	fi
}



function test1 {
	for i in ${SIZE_ARR[*]}; do
		for j in `seq 0 $AROUND_SIZE`; do
			sz=$((i + j - AROUND_SIZE / 2))
			if [ $sz -le 0 ]; then
				continue
			fi

			for k in ${CHUNK_ARR[*]}; do
				for l in `seq 0 $AROUND_CHUNK`; do
					chunk=$((k + l - (AROUND_CHUNK / 2) ))
					if [ $chunk -lt 0 -o $chunk -gt $sz ]; then
						continue
					fi

					for offset in ${OFFSET_ARR[*]}; do

						test_size $sz sha256 sha256sum $chunk $offset
						test_size $sz sha512 sha512sum $chunk $offset
					done
				done
			done
		done
	done
}

insmod_cmd="insmod ./sha_hash_test.ko filename=$TESTFILE"
eval $insmod_cmd
if [ $? -ne 0 ]; then
	echo "Failed to load sha_hash_test."
	exit 1
fi

#test 1a
AROUND_SIZE=2
AROUND_CHUNK=0
SIZE_ARR=(16000000 4194304)
CHUNK_ARR=(0)
OFFSET_ARR=(7 63 64 4095 4096 65535)
test1

#test 1b
AROUND_SIZE=2
AROUND_CHUNK=2
SIZE_ARR=(16000000 7000000 4194304)
CHUNK_ARR=(65536 393216 1048576)
OFFSET_ARR=(7 63 64 4095 4096 65535)
test1

#test 1c
AROUND_SIZE=2
AROUND_CHUNK=2
SIZE_ARR=(1048576 768432 524288 393216 262144 131072 65536 32768 16384 8192 4096 512 256 128 96 64 16 8 4)
CHUNK_ARR=(0 64 256 4096 8192 16384 32768 65536 131072 262144 393216 524288 1048576 )
OFFSET_ARR=(1 15 63 64 65 254 255 256 4095 4096 4097 65534 65535)
test1

rmmod sha_hash_test


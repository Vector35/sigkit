find . -iname '*.deb' | (while read line; do
		arch=`echo $line | awk -F/ '{print $3}'`
		if [[ $arch = amd64 || $arch = arm64 || $arch = armel || $arch = armhf || $arch = i386 || $arch = lpia || $arch = powerpc ]]; then
				echo "$line"
		fi
done) | parallel -j 3 "process-deb.sh {}"

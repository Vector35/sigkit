#!/bin/bash
debfile=$1
pushd `dirname $debfile`
debfilename=`basename $debfile`
echo Now processing $debfilename
debfile_extract=${debfilename%.*};
if [ -d $debfile_extract ]; then
				echo $debfile_extract already exists, exiting
				exit
fi
dpkg-deb -x $debfilename $debfile_extract
pushd $debfile_extract
for libfile in `find . -iname '*.a'`; do
		f=`basename $libfile`
		if [[ $f = libasan.a || $f = libtsan.a ]]; then
				echo Skipping $libfile
				continue
		fi
		pushd `dirname $libfile`
		echo ..Now processing $f
		g=${f%.*};
		if [ ! -d $g ]; then
				mkdir -p $g
				pushd $g
				ar vx ../$f >> ../"$g"_log.txt
				python3 ~/sigkit/batch_process.py "*.o" ../"$g".pkl ../"$g"_checkpoint.pkl >> ../"$g"_log.txt 2>&1
				rm -f *.o # free disk space
				popd
		else
				echo Skipping existing $g
		fi
		popd
done
g=objs
python3 ~/sigkit/batch_process.py "**/*.o" "$g".pkl "$g"_checkpoint.pkl >> "$g"_log.txt 2>&1
find . -iname "*.so" -delete
find . -iname "*.x" -delete
find . -iname "*.h" -delete
popd
popd
TAR_DIR="tarballs"

LOG="error.log"
compilers=("gcc" "clang" "tcc")

compile () {
	base=`basename $1 .tar.gz`
	for compiler in "${compilers[@]}"; do
		dir="$compiler""_$base"
		if [ ! -d "$dir" ]; 
		then
			mkdir -p $dir
			tar xf $TAR_DIR/$1 -C $dir --strip-components 1
			cd $dir
			CC=$compiler ./configure
			if [ $? -ne 0 ]; then
				echo "Error during configure, $compiler $base" >> $LOG
			fi
			make
			if [ $? -ne 0 ]; then
				echo "Error during make, $compiler $base" >> $LOG
			fi
			cd ..
		fi
	done
}

echo "" > $LOG
compile bash-4.4.18.tar.gz
compile grep-2.28.tar.gz 
compile tar-1.27.tar.gz 
compile patch-2.7.tar.gz
compile bc-1.07.tar.gz 
compile wget-1.20.tar.gz
compile nano-4.9.2.tar.gz
compile sed-4.8.tar.gz
compile gzip-1.3.14.tar.gz
#compile autoconf-2.69.tar.gz
#compile autogen-5.18.7.tar.gz 
#compile bison-3.5.4.tar.gz 

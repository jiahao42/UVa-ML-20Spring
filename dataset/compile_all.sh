TAR_DIR="tarballs"

compile () {
	base=`basename $1 .tar.gz`
	dir="$2_$base"
	if [ ! -d "$dir" ]; 
	then
		mkdir -p $dir
		tar xf $TAR_DIR/$1 -C $dir --strip-components 1
		cd $dir
		CC=$2 ./configure
		make
		cd ..
	fi
}


compile bash-4.4.18.tar.gz gcc
compile bash-4.4.18.tar.gz clang
compile bash-4.4.18.tar.gz tcc
compile grep-2.28.tar.gz gcc
compile grep-2.28.tar.gz clang
compile grep-2.28.tar.gz tcc
compile tar-1.27.tar.gz gcc
compile tar-1.27.tar.gz clang
compile tar-1.27.tar.gz tcc



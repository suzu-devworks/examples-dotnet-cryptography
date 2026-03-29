#!/usr/bin/bash

# This script upgrades OpenSSL to version 3.3.x and later on a Debian-based system.

target_ver="3.5.5"
echo "Upgrading to OpenSSL $target_ver..."

# Update the package list and install necessary dependencies
sudo apt update -y
sudo apt install -y \
    build-essential \
    wget \
    zlib1g-dev \
    libssl-dev \

# Download the latest OpenSSL source code
mkdir -p temp/
if [ -d "temp/openssl-$target_ver" ]; then
    echo "OpenSSL $target_ver source code already exists. Skipping download."
else
    echo "Downloading OpenSSL $target_ver source code..."
    wget -P temp/ https://github.com/openssl/openssl/releases/download/openssl-$target_ver/openssl-$target_ver.tar.gz
    tar -xzf temp/openssl-$target_ver.tar.gz -C temp/
fi

# Build and install OpenSSL
echo "Building and installing OpenSSL $target_ver..."
cd temp/openssl-$target_ver
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
# spell-checker: words openssldir
make -j$(nproc)

# Install the new OpenSSL version
sudo make install

# Update the shared library cache
echo "/usr/local/ssl/lib64" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig -v

# update environment variables
export PATH="/usr/local/ssl/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/ssl/lib:$LD_LIBRARY_PATH"
grep -qF 'export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH' ~/.bashrc \
    || echo 'export LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
grep -qF 'export PATH=/usr/local/ssl/bin:$PATH' ~/.bashrc \
    || echo 'export PATH=/usr/local/ssl/bin:$PATH' >> ~/.bashrc

# Verify the installation
installed_ver=$(openssl version | awk '{print $2}')
if [[ "$installed_ver" == "$target_ver" ]]; then
    echo "OpenSSL $target_ver has been successfully installed."
else
    echo "Error: OpenSSL version $installed_ver is installed instead of $target_ver."
    exit 1
fi

# Clean up
cd ../../
rm -rf temp/openssl-$target_ver
rm -f temp/openssl-$target_ver.tar.gz

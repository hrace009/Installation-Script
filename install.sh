#!/bin/bash

# Define log files
CURRENT_DIR=$PWD
LOGFILE="$CURRENT_DIR/install.log"
ERRORFILE="$CURRENT_DIR/install_error.log"

log() {
  local message="$1"
  local type="$2"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  local color
  local endcolor="\033[0m"

  case "$type" in
    "info") color="\033[38;5;79m" ;;
    "success") color="\033[1;32m" ;;
    "error") color="\033[1;31m" ;;
    *) color="\033[1;34m" ;;
  esac

  echo -e "${color}${timestamp} - ${message}${endcolor}"
}

# Error handler function  
handle_error() {
  local exit_code=$1
  local error_message="$2"
  log "Error: $error_message (Exit Code: $exit_code)" "error"
  exit $exit_code
}

# Function to check for command availability
command_exists() {
  command -v "$1" &> /dev/null
}

check_os() {
    if ! [ -f "/etc/debian_version" ]; then
        echo "Error: This script is only supported on Debian-based systems."
        exit 1
    fi
}

# Function to Install the script pre-requisites
install_pre_reqs() {
    log "Installing pre-requisites" "info"

    # Run 'apt-get update'
    if ! apt-get update -y; then
        handle_error "$?" "Failed to run 'apt-get update'"
    fi

    # Run 'apt-get install'
    if ! apt-get install -y apt-transport-https ca-certificates curl gnupg; then
        handle_error "$?" "Failed to install packages"
    fi

    if ! mkdir -p /usr/share/keyrings; then
      handle_error "$?" "Makes sure the path /usr/share/keyrings exist or run ' mkdir -p /usr/share/keyrings' with sudo"
    fi

    rm -f /usr/share/keyrings/nodesource.gpg || true
    rm -f /etc/apt/sources.list.d/nodesource.list || true

    # Run 'curl' and 'gpg' to download and import the NodeSource signing key
    if ! curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg; then
      handle_error "$?" "Failed to download and import the NodeSource signing key"
    fi

    # Explicitly set the permissions to ensure the file is readable by all
    if ! chmod 644 /usr/share/keyrings/nodesource.gpg; then
        handle_error "$?" "Failed to set correct permissions on /usr/share/keyrings/nodesource.gpg"
    fi
}

# Function to configure the Repo
configure_repo() {
    local node_version=$1

    arch=$(dpkg --print-architecture)
    if [ "$arch" != "amd64" ] && [ "$arch" != "arm64" ] && [ "$arch" != "armhf" ]; then
      handle_error "1" "Unsupported architecture: $arch. Only amd64, arm64, and armhf are supported."
    fi

    echo "deb [arch=$arch signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$node_version nodistro main" | tee /etc/apt/sources.list.d/nodesource.list > /dev/null

    # N|solid Config
    echo "Package: nsolid" | tee /etc/apt/preferences.d/nsolid > /dev/null
    echo "Pin: origin deb.nodesource.com" | tee -a /etc/apt/preferences.d/nsolid > /dev/null
    echo "Pin-Priority: 600" | tee -a /etc/apt/preferences.d/nsolid > /dev/null

    # Nodejs Config
    echo "Package: nodejs" | tee /etc/apt/preferences.d/nodejs > /dev/null
    echo "Pin: origin deb.nodesource.com" | tee -a /etc/apt/preferences.d/nodejs > /dev/null
    echo "Pin-Priority: 600" | tee -a /etc/apt/preferences.d/nodejs > /dev/null

    # Run 'apt-get update'
    if ! apt-get update -y; then
        handle_error "$?" "Failed to run 'apt-get update'"
    else
        log "Repository configured successfully."
        log "To install Node.js, run: apt-get install nodejs -y" "info"
        log "You can use N|solid Runtime as a node.js alternative" "info"
        log "To install N|solid Runtime, run: apt-get install nsolid -y \n" "success"
    fi
}

# Function to print progress message
print_progress() {
    echo -e "\e[36m$1\e[0m" | tee -a $LOGFILE
}

# Function to print error message
print_error() {
    echo -e "\e[31m$1\e[0m" | tee -a $ERRORFILE
}

# Function to print warning message
print_warning() {
    echo -e "\e[33m$1\e[0m" | tee -a $LOGFILE
}

# Function to check exit code and print completion message
check_status() {
    if [ $1 -eq 0 ]; then
        print_progress "Completed."
    else
        print_error "Error during installation. Exit code: $1"
    fi
}

# Function to check if a package is installed
is_package_installed() {
    dpkg -l | grep -q "^ii  $1 "
}

# Function to download file using wget if it does not exist
download_if_not_exists() {
    local url=$1
    local output_file=$2

    if [ -f "$output_file" ]; then
        print_warning "The file '$output_file' already exists. Skipping download."
    else
        print_progress "Downloading '$output_file'..."
        wget -q "$url" -O "$output_file"
        if [ $? -eq 0 ]; then
            print_progress "Downloading '$output_file' completed."
        else
            print_error "Failed to download '$output_file'."
        fi
    fi
}

# System update and upgrade
print_progress "Updating and upgrading the system..."
{ 
  echo "y" | sudo apt update >> $LOGFILE 2>> $ERRORFILE && 
  echo "y" | sudo apt upgrade >> $LOGFILE 2>> $ERRORFILE 
}
check_status $?

# Allow root access via SSH
print_progress "Allowing root access via SSH..."
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo service ssh restart
check_status $?

# Prompt for the desired password for the root user
read -s -p "Enter a new 6-digit password for the root user: " new_root_password
echo

# Check if the entered password is strong enough
if [ ${#new_root_password} -lt 6 ]; then
    print_error "Password must contain at least 6 characters, restart the script."
    exit 1
fi

# Change the root user password
print_progress "Changing the root user password..."
echo "root:$new_root_password" | sudo chpasswd
check_status $?
# NTP Installation
print_progress "Installing NTP..."
sudo apt-get install -y ntp >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Time zone setting
print_progress "Setting time zone..."
sudo timedatectl set-timezone Asia/Jakarta >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Check if Mariadb is already installed
print_progress "Verifying MariaDB installation..."
if dpkg -l | grep -q "^ii.*mariadb-server "; then
    print_warning "MariaDB is already installed. Skipping installation."
    mariadb_installed=1
else
    mariadb_installed=0
fi

# If MariaDB is not installed, perform installation and configuration
if [ $mariadb_installed -eq 0 ]; then
    # MariaDB Installation
    print_progress "Installing MariaDB..."
    sudo apt-get -y install mariadb-server mariadb-client >> $LOGFILE 2>> $ERRORFILE
    sudo systemctl restart mariadb >> $LOGFILE 2>> $ERRORFILE
    sudo sed -i 's/^bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf >> $LOGFILE 2>> $ERRORFILE
    sudo systemctl restart mariadb >> $LOGFILE 2>> $ERRORFILE
    check_status $?

    # Ask if you want to set the password for MariaDB root
    read -p "Do you want to set a password for the MariaDB root user? (y/n): " set_root_password
    if [[ $set_root_password == "y" || $set_root_password == "Y" ]]; then
        read -s -p "Enter the new password for the MariaDB root user: " root_password
        echo

        # Set password directly via MySQL
        print_progress "Setting password for MariaDB root user..."
        sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$root_password'; FLUSH PRIVILEGES;" >> $LOGFILE 2>> $ERRORFILE
        check_status $?
    else
        print_warning "Password for MariaDB root user will not be set."
    fi
    
fi

# Request new username and password
read -p "Do you want to create a new MariaDB user? (y/n): " create_new_user
if [[ $create_new_user == "y" || $create_new_user == "Y" ]]; then
    read -p "Enter the name of the new MariaDB user: " username
    read -s -p "Enter the password for the new MariaDB user: " password
    echo

    # Create new user with permissions similar to MariaDB root
    print_progress "Creating new user with permissions similar to MariaDB root..."
    sudo mysql -u root -p"$root_password" -e "CREATE USER '$username'@'%' IDENTIFIED BY '$password'; GRANT ALL PRIVILEGES ON *.* TO '$username'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;" >> $LOGFILE 2>> $ERRORFILE
    check_status $?
else
    print_warning "No new MariaDB users will be created."
fi

# Restore the original PATH
export PATH="${PATH#/usr/bin:}"

# OpenJDK 11 JRE and Mono Complete Installation
print_progress "Installing OpenJDK 11 JRE and Mono Complete..."
if ! dpkg -l | grep -q "^ii.*openjdk-11-jre "; then
    echo "y" | sudo apt-get -y install openjdk-11-jre mono-complete >> $LOGFILE 2>> $ERRORFILE
fi
check_status $?

# Utilities Installation
print_progress "Installing utilities..."
echo "y" | sudo apt-get -y install htop curl wget ipset net-tools tzdata p7zip-full unrar zip >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Setting up the environment to run 64-bit daemons
print_progress "Setting up environment to run 64-bit daemons..."
echo "y" | sudo apt-get -y install libxml2 >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt-get -y install libstdc++5 >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt-get -y install libpcre3-dev >> $LOGFILE 2>> $ERRORFILE
download_if_not_exists "http://security.ubuntu.com/ubuntu/pool/main/o/openssl1.0/libssl1.0.0_1.0.2n-1ubuntu5.13_amd64.deb" "libssl1.0.0_1.0.2n-1ubuntu5.13_amd64.deb"
echo "y" | sudo apt install -y ./libssl1.0.0_1.0.2n-1ubuntu5.13_amd64.deb >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Setting up the environment to run 32-bit daemons
print_progress "Setting up environment to run 32-bit daemons..."
echo "y" | sudo dpkg --add-architecture i386 >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt-get update >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt-get -y install lib32z1-dev >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt-get -y install libc6-i386 >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt-get -y install libgcc1:i386 >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Bug fix in gacd
print_progress "Fixing error in gacd..."
echo "y" | sudo apt-get -y install libxml2 >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Required to run glinkd
print_progress "Setting up to run glinkd..."
echo "y" | sudo apt-get -y install libstdc++5:i386 >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Required to run gamed and gdeliveryd
print_progress "Setting up to run gamed and gdeliveryd..."
echo "y" | sudo apt-get -y install libpcre3-dev:i386 >> $LOGFILE 2>> $ERRORFILE
sudo ln -s /lib/i386-linux-gnu/libpcre.so.3.13.3 /lib/i386-linux-gnu/libpcre.so.0 >> $LOGFILE 2>> $ERRORFILE
download_if_not_exists "http://security.ubuntu.com/ubuntu/pool/main/o/openssl1.0/libssl1.0.0_1.0.2n-1ubuntu5.13_i386.deb" "libssl1.0.0_1.0.2n-1ubuntu5.13_i386.deb"
echo "y" | sudo apt install -y ./libssl1.0.0_1.0.2n-1ubuntu5.13_i386.deb >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Additional installation of libssl1.0.0 and fixing symbolic links
print_progress "Installing libssl1.0.0 and fixing symlinks..."
echo "y" | sudo apt-get install libssl1.0.0 libssl-dev >> $LOGFILE 2>> $ERRORFILE
cd /lib/x86_64-linux-gnu
sudo ln -s libssl.so.1.0.0 libssl.so.10 >> $LOGFILE 2>> $ERRORFILE
sudo ln -s libcrypto.so.1.0.0 libcrypto.so.10 >> $LOGFILE 2>> $ERRORFILE
cd /lib32
sudo ln -s /usr/lib32/libgcc_s.so.1 /lib32/libgcc_s.so.1 >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Final cleaning
print_progress "Performing final cleaning..."
echo "y" | sudo apt update >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt dist-upgrade >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt clean >> $LOGFILE 2>> $ERRORFILE
echo "y" | sudo apt autoremove >> $LOGFILE 2>> $ERRORFILE
rm -rf ~/.local/share/Trash/*
sudo rm -rf /tmp/* >> $LOGFILE 2>> $ERRORFILE
check_status $?

# System update and upgrade
print_progress "Updating and upgrading the system..."
{ 
  echo "y" | sudo apt update >> $LOGFILE 2>> $ERRORFILE && 
  echo "y" | sudo apt upgrade >> $LOGFILE 2>> $ERRORFILE 
}
check_status $?

# Install required packages
print_progress "Installing required packages..."
    sudo apt install -y \
    build-essential libxml2-dev libbz2-dev libcurl4-openssl-dev libjpeg-dev \
    libpng-dev libwebp-dev libfreetype6-dev libzip-dev libonig-dev libssl-dev \
    libsqlite3-dev libxpm-dev libreadline-dev libtidy-dev libxslt1-dev \
    libicu-dev libldap2-dev libsodium-dev libedit-dev libargon2-dev \
    libmcrypt-dev libgd-dev libkrb5-dev libpspell-dev libdb-dev libgmp-dev \
    libpq-dev libpq5 libsqlite3-dev libtool unixodbc-dev libmagickwand-dev \
    libc-client2007e-dev libevent-dev re2c pkg-config zlib1g-dev \
    libpcre2-dev libxmlrpc-epi-dev libexif-dev libmhash-dev git cmake >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Fix imap build issues
print_progress "Fixing imap build issues..."
sudo ln -s /usr/lib/x86_64-linux-gnu/libc-client.a /usr/lib/ >> $LOGFILE 2>> $ERRORFILE

# Create user and group for PHP-FPM
print_progress "Creating user and group for PHP-FPM..."
sudo useradd -m -s /bin/bash hrace009 >> $LOGFILE 2>> $ERRORFILE

# Download and Extract PHP 8.3.23
print_progress "Downloading and installing PHP 8.3.23..."
    cd /usr/local/src
    download_if_not_exists "https://www.php.net/distributions/php-8.3.23.tar.gz" "/usr/local/src/php-8.3.23.tar.gz" >> $LOGFILE 2>> $ERRORFILE
    sudo tar -xzf php-8.3.23.tar.gz >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Configure PHP with Required Modules
print_progress "Configuring PHP with required modules..."
    cd /usr/local/src/php-8.3.23
    sudo ./configure --prefix=/usr/local/php8.3 \
    --with-config-file-path=/usr/local/php8.3/etc \
    --enable-fpm --with-fpm-user=hrace009 --with-fpm-group=hrace009 \
    --with-bz2 --with-curl --with-openssl --enable-mbstring --enable-soap \
    --enable-intl --with-xsl --enable-calendar --with-zlib --enable-gd --with-jpeg --with-webp --with-freetype \
    --with-jpeg --with-webp --with-freetype --enable-exif --with-gettext \
    --with-kerberos --with-ldap --enable-sockets --enable-pcntl \
    --with-readline --with-iconv --with-mysqli --with-pdo-mysql \
    --with-pdo-odbc=unixODBC,/usr --with-pdo-sqlite --enable-sysvmsg \
    --enable-sysvsem --enable-sysvshm --with-sodium --with-zip \
    --enable-shmop --with-imap --with-imap-ssl --with-pear --enable-opcache \
    --enable-bcmath --with-mhash --with-pspell \
    --enable-xml --with-libxml --enable-tokenizer --with-xsl >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Compile and Install PHP
print_progress "Compiling and installing PHP..."
    cd /usr/local/src/php-8.3.23
    sudo make -j$(nproc) >> $LOGFILE 2>> $ERRORFILE
    sudo make install >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Configure PHP-FPM
print_progress "Configuring PHP-FPM..."
    sudo cp php.ini-production /usr/local/php8.3/etc/php.ini >> $LOGFILE 2>> $ERRORFILE
    sudo cp /usr/local/php8.3/etc/php-fpm.conf.default /usr/local/php8.3/etc/php-fpm.conf >> $LOGFILE 2>> $ERRORFILE
    sudo cp /usr/local/php8.3/etc/php-fpm.d/www.conf.default /usr/local/php8.3/etc/php-fpm.d/www.conf >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Add PHP 8.3 to your shell profile:
print_progress "Add PHP 8.3 to your shell profile..."
echo 'export PATH=/usr/local/php8.3/bin:$PATH' | sudo tee -a /etc/profile.d/php83.sh
sudo chmod +x /etc/profile.d/php83.sh

# Install PECL Extensions
print_progress "Setup PEAR and PECL..."
    export IMAGEMAGICK_PREFIX=/usr
    yes '' | /usr/local/php8.3/bin/pecl install imagick >> $LOGFILE 2>> $ERRORFILE
    export MCRYPT_PREFIX=/usr
    yes '' | /usr/local/php8.3/bin/pecl install mcrypt >> $LOGFILE 2>> $ERRORFILE
    sudo /usr/local/php8.3/bin/pecl install xmlrpc >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Enable installed extensions
print_progress "Enabling installed extensions..."
    sudo sed -i '/^;*extension=imagick.so/s/^;*//' /usr/local/php8.3/etc/php.ini || echo 'extension=imagick.so' >> /usr/local/php8.3/etc/php.ini
    sudo sed -i '/^;*extension=mcrypt.so/s/^;*//' /usr/local/php8.3/etc/php.ini || echo 'extension=mcrypt.so' >> /usr/local/php8.3/etc/php.ini
    sudo sed -i '/^;*extension=xmlrpc.so/s/^;*//' /usr/local/php8.3/etc/php.ini || echo 'extension=xmlrpc.so' >> /usr/local/php8.3/etc/php.ini
check_status $?


#Create PHP-FPM Systemd Service
print_progress "Creating PHP-FPM systemd service..."
sudo tee /etc/systemd/system/php8.3-fpm.service > /dev/null <<EOF
[Unit]
Description=The PHP 8.3 FastCGI Process Manager
After=network.target

[Service]
Type=simple
PIDFile=/run/php8.3-fpm.pid
ExecStart=/usr/local/php8.3/sbin/php-fpm --nodaemonize --fpm-config /usr/local/php8.3/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 \$MAINPID
User=hrace009
Group=hrace009

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reexec
sudo systemctl enable --now php8.3-fpm
# Start PHP-FPM service
print_progress "Starting PHP-FPM service..."
sudo systemctl start php8.3-fpm >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Install and Configure NGINX 1.29 with Brotli
print_progress "Installing NGINX 1.29 with Brotli support..."
sudo apt install -y brotli zlib1g-dev libpcre3 libpcre3-dev libssl-dev >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Download Brotli source code
print_progress "Downloading Brotli source code..."
    cd /usr/local/src
    sudo git clone https://github.com/google/ngx_brotli.git >> $LOGFILE 2>> $ERRORFILE
    cd ngx_brotli && sudo git submodule update --init --recursive >> $LOGFILE 2>> $ERRORFILE
check_status $?

print_progress "Compiling Brotli..."
    cd /usr/local/src
    rm -rf ngx_brotli/deps/brotli/out
    cd ngx_brotli/deps/brotli
    sudo mkdir out && cd out >> $LOGFILE 2>> $ERRORFILE
    sudo cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_CXX_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_INSTALL_PREFIX=./installed .. >> $LOGFILE 2>> $ERRORFILE
    sudo cmake --build . --config Release --target brotlienc >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Install NGINX with Brotli
print_progress "Downloading and installing NGINX 1.29.0..."
    cd /usr/local/src
    download_if_not_exists "https://nginx.org/download/nginx-1.29.0.tar.gz" "nginx-1.29.0.tar.gz" >> $LOGFILE 2>> $ERRORFILE
    sudo tar -xzvf nginx-1.29.0.tar.gz >> $LOGFILE 2>> $ERRORFILE
check_status $?

print_progress "Configuring NGINX with Brotli support..."
    cd /usr/local/src/nginx-1.29.0
    sudo ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --pid-path=/var/run/nginx.pid \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_gzip_static_module \
        --add-module=/usr/local/src/ngx_brotli >> $LOGFILE 2>> $ERRORFILE
check_status $?

print_progress "Compiling and installing NGINX..."
cd /usr/local/src/nginx-1.29.0
    sudo make -j$(nproc) >> $LOGFILE 2>> $ERRORFILE
    sudo make install >> $LOGFILE 2>> $ERRORFILE
check_status $?
#Create NGINX Systemd Service
print_progress "Creating NGINX systemd service..."
sudo tee /etc/systemd/system/nginx.service > /dev/null <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
PIDFile=/var/run/nginx.pid
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reexec
sudo systemctl enable --now nginx
# Start NGINX service
print_progress "Starting NGINX service..."
sudo systemctl start nginx >> $LOGFILE 2>> $ERRORFILE
check_status $?

echo "All Done! PHP 8.3.23 and NGINX 1.29 with Brotli support have been installed successfully."

# Node.js and N|solid Installation
print_progress "Installing Node.js and N|solid..."
# Define Node.js version
NODE_VERSION="18.x"

# Check OS
check_os

# Main execution
install_pre_reqs || handle_error $? "Failed installing pre-requisites"
configure_repo "$NODE_VERSION" || handle_error $? "Failed configuring repository"
sudo apt-get install nodejs -y >> $LOGFILE 2>> $ERRORFILE
check_status $?

# Restart the system
print_progress "Restarting the system..."
sudo reboot

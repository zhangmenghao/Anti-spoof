# Kernel Version HCF Installing Guide

In our paper, a Kernel version HCF is achieved based on linux 4.9.0 to compare with NetHCF. This doucument shows how to install Kernel version HCF on Ubuntu 16.04.

## Downloading and Updating Kernel Code

First, dowload linux kernel 4.9.0 from [here](https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/). Then, unzip it using the following command.(If you download Kernel code in other format, you have to use other commands to unzip)

    tar -zxvf linux-4.9.tar.gz

Using the patch file to upload kernel code. (If your patch file and kernel code are in different directory, just change the path in the command.)

    patch linux-4.9/net/ipv4/ip_input.c ip_input.patch
    
Now you get the kernel which contains HCF, you can see deatils and change the content of ip2hc table in ip_input.c.

## Compiling and Installing New Kernel

Before compiling the kernrl code, you may have to install some tools.

    sudo apt-get install build-essential kernel-package libncurses5-dev libssl-dev libelf-dev
    
Then, enter the kernel path and do configurations. If you don't know what to config, just use the default configuration.

    cd linux-4.9
    make menuconfig
    
After configuration, you can compile kernel now.

    make
    
It will cost a long time to compile the code, after compilaton, you can use the following command to install drivers (not essential) and kernel image.

    make modules_install
    make install
    
And the kernel is installed. You can change the kerne by modifying the gurb configuration file or enter gurb menu when you restart your machine.


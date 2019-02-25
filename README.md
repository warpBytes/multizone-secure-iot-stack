# MultiZone Secure IoT Stack

The first Secure IoT Stack for RISC-V – a secure implementation of freeRTOS with hardware enforced separation between the OS, TCP/IP stack and root of trust with TLS 1.3 / ECC for secure Internet of Things applications.

This reference implementation combines freeRTOS, picoTCP, wolfSSL and Root of Trust as physically isolated TEE zones
 - X300 Bitstream : Rocket core with Ethernet Peripheral for Xilinx A7-35T Arty Board
 - MultiZone Security Trusted Execution Environment configured for 4 Zones
 - Zone 1: FreeRTOS with 3 tasks (CLI, LED PWM, Robot)
 - Zone 2: PicoTCP + wolfSSL TLS 1.3 / ECC terminating Ethernet port
 - Zone 3: Root of Trust
 - Zone 4: USB UART Console

### Installation ###

The MultiZone Secure IoT Stack supports a multitude of hardware targets. For a complete evaluation of the framework it is reccomended to use the open source softcore X300 developed by Hex Five Security. It is an enhanced version of the E300 SoC (Rocket) maintained by SiFive - entirely free for commercial and non-commercial use. Like the E300, the X300 is designed to be programmed onto a Xilinx Artix-7 35T Arty FPGA.

Hardware prerequisites: Xilinx Artix-7 35T Arty, Xilinx Vivado, Olimex ARM-USB-TINY-H Debugger
 - Download the X300 bitstream .mcs file from https://github.com/hex-five/multizone-fpga/releases
 - Program the .mcs file to the Arty board using Vivado

Software requirements: Install the reference RISC-V toolchain for Linux - directions specific to a fresh Ubuntu 18.04 LTS, other Linux distros generally a subset. To connect via TLS you'll need a TLS 1.3 client. If you itend to use OpenSSL, make sure you have version 1.1.1a or greater. At the time of writing, OpenSSL included in Debian 9 (stretch) and Ubuntu 18.04.2 is version 1.1.0, which does not support TLS 1.3.   
 ```
 sudo apt update
 sudo apt upgrade -y
 sudo apt install git make default-jre libftdi1-dev
 sudo ln -s /usr/lib/x86_64-linux-gnu/libmpfr.so.6 /usr/lib/x86_64-linux-gnu/libmpfr.so.4
 wget https://github.com/hex-five/multizone-sdk/releases/download/v0.1.0/riscv-gnu-toolchain-20181226.tar.xz
 tar -xvf riscv-gnu-toolchain-20181226.tar.xz
 wget https://github.com/hex-five/multizone-sdk/releases/download/v0.1.0/riscv-openocd-20181226.tar.xz
 tar -xvf riscv-openocd-20181226.tar.xz
 git clone https://github.com/hex-five/multizone-secure-iot-stack
 cd multizone-secure-iot.stack
 git submodule update --init --recursive
 sudo apt-get install libusb-0.1-4
 sudo apt-get install screen
```

If you have not already done so, you need to edit or create a file to place the USB devices until plugdev group so you can access them without root privileges:
```
sudo vi /etc/udev/rules.d/99-openocd.rules
```
Then place the following text in that file
```
# These are for the HiFive1 Board
SUBSYSTEM=="usb", ATTR{idVendor}=="0403",
ATTR{idProduct}=="6010", MODE="664", GROUP="plugdev"
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403",
ATTRS{idProduct}=="6010", MODE="664", GROUP="plugdev"
# These are for the Olimex Debugger for use with E310 Arty Dev Kit
SUBSYSTEM=="usb", ATTR{idVendor}=="15ba",
ATTR{idProduct}=="002a", MODE="664", GROUP="plugdev"
SUBSYSTEM=="tty", ATTRS{idVendor}=="15ba",
ATTRS{idProduct}=="002a", MODE="664", GROUP="plugdev"
```
Detach and re-attach the USB devices for these changes to take effect.

Add environment variables and a path to allow the Makefiles to find the toolchain

edit ~/.bashrc and ~/.profile and place the following text at the bottom of both files.
```
export RISCV=/home/<username>/riscv-gnu-toolchain-20181226
export OPENOCD=/home/<username>/riscv-openocd-20181226
export PATH="$PATH:/home/<username>/riscv-gnu-toolchain-20181226/bin"
```
Close and restart the terminal session for these changes to take effect.

### Compile and Upload the Project to the Arty Board ###

```
cd multizone-secure-iot-stack/
make clean
make
```

This will result in a HEX file that is now ready to upload to the Arty board. There is know issue with the first upload after board power-on: if it upload takes more than a few seconds you may want to kill the openocd/gdb process and repeat the make load. Otherwise the first load may take up to two minutes.
```
make load
```

### Operate the Demo ###

The system contains four zones:
 - Zone 1: FreeRTOS with three tasks - CLI, LED PWM and Robot Control plus three interrupt handlers (BTN0-2) 
   - Press enter for a list of support commands
 - Zone 2: TCP/IP + TLS Stack (picoTCP + wolfSSL) - accessable via ethernet port
   - Ping to 192.168.0.2 (default address, set in Makefile)
   - Telnet to port 23 or
   - Connect via TLS: stty -icanon -echo && openssl s_client -tls1_3 -crlf -nocommands -connect 192.168.0.2:443
 - Zone 3: Root of Trust and Session Key Storage
 - Zone 4: MultiZone Console - access via USB UART at 115,200 buard 8N1
 
 Press enter for a list of supported commands

### Crypto specs ###
```
TLSv1.3, Cipher TLS_AES_128_GCM_SHA256
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: ECDH, P-256, 256 bits
Server public key is 256 bit
Private Key ASN1 OID: prime256v1
Private Key NIST CURVE: P-256
```

### X300 specs ###

X300 is an enhanced version of [SiFive's Freedom E300
Platform](https://github.com/sifive/freedom/tree/3624efff1819e52cec30c72f9085158189f8b53f)
to support [MultiZone](https://hex-five.com/products/) and IoT applications.
The X300 is completely open source and free of charge for commercial and non-commercial use.

| E300             | X300                                         |
| ---------------- | -------------------------------------------- |
| RV32ACIM         | RV32ACIMU                                    |
| 32.5 MHz clock   | 65 MHz clock                                 |
| 2 HW breakpoints | 8 HW breakpoints                             |
| no Ethernet core | Xilinx EthernetLite Ethernet core            |
| 1-way icache     | 4-way icache                                 |
| no ITIM          | ITIM at 0x0800\_0000                         |
| 16 kB DTIM       | 64 kB DTIM                                   |
| no perf counters | 2 perf counters, hpmcounter3 and hpmcounter4 |
| no CLICs         | 3 CLICs (BTN0, BTN1 and BTN2)                |

### Legalities ###

Please remember that export/import and/or use of strong cryptography software, providing cryptography hooks, or even just communicating technical details about cryptography software is illegal in some parts of the world. So when you import this software to your country, re-distribute it from there or even just email technical suggestions or even source patches to the authors or other people you are strongly advised to pay close attention to any laws or regulations which apply to you. Hex Five Security, Inc. and the authors of the software included in this repository are not liable for any violations you make here. So be careful, it is your responsibility. 

### For More Information ###

See manula.pdf or visit [http://www.hex-five.com](https://www.hex-five.com)

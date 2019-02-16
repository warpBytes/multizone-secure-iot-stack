# MultiZone Secure IoT Stack

The first Secure IoT Stack for RISC-V – a secure implementation of freeRTOS with hardware enforced separation between the OS, TCP/IP stack and root of trust with TLS 1.3 for secure Internet of Things applications.

This reference implementation combines freeRTOS, picoTCP, wolfSSL and Root of Trust as physically isolated TEE zones
 - X300 Bitstream : Rocket core with Ethernet Peripheral for Xilinx A7-35T Arty Board
 - MultiZone Security Trusted Execution Environment configured for 4 Zones
 - Zone 1: FreeRTOS with 3 tasks (CLI, LED PWM, Robot)
 - Zone 2: PicoTCP + wolfSSL TLS 1.3 terminating Ethernet port
 - Zone 3: Root of Trust
 - Zone 4: USB UART Console

This repository, maintained by Hex Five Security, makes it easy to build a robust Secure IoT Stack with four Zones based on MultiZone Security.

### Installation ###

Hex Five created a modified version of the Rocket SoC called teh X300 with an additional Ethernet port and improved performance

Upload the X300 Bitstream to a Xilinx Artik-7 35T Arty FPGA board
prerequisites: Xilinx Vivado, Olimex ARM-USB-TINY-H Debugger
 - Download the X300 bitstream .mcs file from https://github.com/hex-five/multizone-fpga/releases
 - Push the .mcs file to the Arty board using Vivado

 Install the reference RISC-V toolchain for Linux - directions specific to a fresh Ubuntu 18.04 LTS, other Linux distros generally a subset
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

This will result in a HEX file that is now ready to upload to the Arty board.  The first time you push this HEX file up it takes about 2 minutes, on subsequent passes it goes much faster.
```
make load
```

### Operate the Demo ###

The system contains four zones:
 - Zone 1: FreeRTOS with three tasks - CLI, LED PWM and Robot Control plus three interrupt handlers (BTN0-2) 
   - Press enter for a list of support commands
 - Zone 2: TCP/IP + TLS Stack (picoTCP + wolfSSL) - accessable via ethernet port
   - Ping to 192.168.0.2 (default address, set in Makefile)
   - Telnet to port 23
   - Secure telnet (TLS) to port 443
 - Zone 3: Root of Trust and Session Key Storage
 - Zone 4: UART Console - access via USB UART at 115,200 buard 8N1
   - Press enter for a list of supported commands

### For More Information ###

See the MultiZone Manual (Pending) or visit [http://www.hex-five.com](https://www.hex-five.com)

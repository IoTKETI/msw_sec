# msw_sec

#### project build

#!/bin/bash

# insgtall libusb, libudev
sudo apt-get install libusb-1.0-0 libusb-1.0-0-dev -y
sudo apt-get install libudev-dev -y

#  download dependancy package
npm install
#  build package
npm run build



## device rulefile
filename : /etc/udev/rules.d/xx-kse300.rules

SUBSYSTEM=="input", GROUP="input", MODE="666"
SUBSYSTEM=="usb",  ATTRS{idVendor}=="25f8", ATTRS{idProduct}=="9002", MODE="666", GROUP="plugdev"
KERNEL=="hidraw*", ATTRS{idVendor}=="25f8", ATTRS{idProduct}=="9002", MODE="666", GROUP="plugdev"

#!/bin/bash

#sudo apt remove libusb-1.0-0 libusb-1.0-0-dev -y
#sudo apt remove libudev-dev -y

# install libusb files
echo " install libusb, libudev "
sudo apt install libusb-1.0-0 libusb-1.0-0-dev -y
sudo apt install libudev-dev -y

# copy rule file
echo " copy device rulefile"
sudo cp -rf *.rules  /etc/udev/rules.d/

# restart udev service
echo " restart udev service"
sudo udevadm control --reload-rules

# build msw_sec
echo " npm install / build"
cd etri_dim
npm install
npm run build

cd ..

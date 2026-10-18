# BLE Full-Band Sniffer

This repository contains the implementation of a full-band BLE sniffer that can monitor all the BLE connections in an area using GPU acceleration.
The system implemented here is described in [this paper](https://ieeexplore.ieee.org/abstract/document/9191479).
The code has been modified to handle float value instead of double, this works better with older GPU
For even older GPU a 32MHz float version is available. 
The code has been tested on a i3-3240 CPU with usrp B200 mini and a GTX1070 with 8GB ram, sample rate at 40MHz.

## Compilation instructions
`cd` into this repository and run:
```
    $ sudo apt-get install libpcap-dev
    $ sudo apt-get install gcc-11 g++-11
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
```

## Running the application
To print an help message with all the parameters accepted by the program, run it with:
```
    $ ./blesniffer --help

To use the float version :
    $ ./blesniffer_float --help
```

## Additional info
If you find this code useful, please consider citing:
```
@inproceedings{cominelli20,
  author={Cominelli, Marco and Patras, Paul and Gringoli, Francesco},
  booktitle={2020 Mediterranean Communication and Computer Networking Conference (MedComNet)}, 
  title={One GPU to Snoop Them All: a Full-Band Bluetooth Low Energy Sniffer}, 
  year={2020},
  volume={},
  number={},
  pages={1-4},
  doi={10.1109/MedComNet49392.2020.9191479}}
```

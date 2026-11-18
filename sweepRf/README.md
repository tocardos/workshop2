# BLE Workshop – RF Spectrum Analyzer

This project combines a Software Defined Radio (SDR) sweep capability with a WebSocket server to analyze and visualize Bluetooth Low Energy (BLE) spectrum data.

## Overview

This system is designed to perform spectrum sweeps, capture BLE packet data, and provide a graphical interface for visualizing the results index.html.

## Components

The project consists of two main components:

1. **Server Script (`server_sweep_hckrf.py`):** This Python script handles the core functionality of the spectrum sweep. It is responsible for reading data (likely from a device like HackRF), setting frequency ranges, defining bin widths, and establishing a WebSocket endpoint for data transmission server_sweep_hckrf.py.
2. **Visualization Interface (`index.html`):** This HTML file provides a user interface for viewing the swept spectrum data. It includes options for selecting colormaps (e.g., Thermal, Viridis), time holds, and viewing BLE channels index.html.

## Setup and Execution

### Prerequisites

You will need Python installed, along with the necessary libraries:  
pip install fastapi uvicorn pyzmq

### Running the Server

Execute the main Python script. You can specify parameters such as bin width, frequency start/stop, and the ZMQ endpoint.

Example run arguments:  
python server_sweep_hckrf.py [--bin-width 2] [--port 8080]

### Visualization

Access the web interface by opening the generated `index.html` file in a web browser.

## Data Flow

The process generally involves:

1. The Python script executes the RF sweep and prepares the data.
2. The data is broadcast via a WebSocket connection to the client.
3. The client displays the spectrum data using the provided HTML interface.

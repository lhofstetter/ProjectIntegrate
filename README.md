<a name="readme-top"></a>

<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Proprietary License][license-shield]][license-url]

# Project Integrate

## Description
Project Integrate aims to automate smart device interactions in homes by tracking users' locations. Unlike traditional systems that rely on motion sensors, our project calculates the distance from the user's device to every smart device in the home. This proximity-based method offers a personalized and adaptive smart home experience.

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#description">Description</a></li>
    <li><a href="#installation">Installation</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#setup-instructions">Setup Instructions</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#built-with">Built With</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## Installation

### Prerequisites
- Raspberry Pi 3 (for the root node)
- Raspberry Pi Zero W (for leaf nodes)
- WiFi antennas compatible with Raspberry Pi
- USB A to Micro-USB adapters for connecting WiFi antennas

### Setup Instructions
1. **Root Node Setup**: Connect the Raspberry Pi 3 to power in one corner of your home and attach the WiFi antenna using the USB adapter.
2. **Leaf Nodes Setup**: Plug each Raspberry Pi Zero W into power at different corners of the house to maximize coverage. Connect each Pi Zero W to the WiFi antennas similarly.
3. **Network Configuration**: Ensure all devices are connected to the same WiFi network for seamless communication.

## Usage
Once installed, the system automatically detects the registered mobile devices and starts tracking their proximity to the smart devices. You can configure actions based on proximity, like turning on lights or playing music as you move through different rooms.

## Built With

- ![Raspberry Pi OS](https://img.shields.io/badge/Raspberry_Pi_OS-A22846?style=for-the-badge&logo=raspberry-pi)
- ![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=cplusplus)
- ![REST API](https://img.shields.io/badge/REST_API-009688?style=for-the-badge)
- ![IPv6](https://img.shields.io/badge/IPv6-585858?style=for-the-badge)

## License
This project is protected under proprietary license terms. Please see the `LICENSE.txt` file for more details.

## Contact
- Luke Hofstetter - [lhofstetter@scu.edu](mailto:lhofstetter@scu.edu)
- Marley Willyoung - [mwillyoung@scu.edu](mailto:lmwillyoung@scu.edu)
- Liam Robertson - [lprobertson@scu.edu](mailto:lprobertson@scu.edu)
- Project Link: [https://github.com/lhofstetter/ProjectIntegrate](https://github.com/lhofstetter/ProjectIntegrate)

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/lhofstetter/ProjectIntegrate.svg?style=for-the-badge
[contributors-url]: https://github.com/lhofstetter/ProjectIntegrate/graphs/contributors
[license-shield]: https://img.shields.io/badge/License-Proprietary-blue.svg?style=for-the-badge
[license-url]: https://github.com/lhofstetter/ProjectIntegrate/blob/master/LICENSE.txt
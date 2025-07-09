#  CloudLAPS for macOS

## Overview
This package aims to bridge the gap between macOS and Windows devices when it comes to local administrator password management,
by (almost) directly porting the MSEndpointmgr team's CloudLAPS client software from Windows to macOS.

## Deployment guide
### Deploy package configuration plist
* Customize the info.plist file to your preferences and deploy to devices
    * Copy info.plist, and edit the empty values to match your MDM bindings and CloudLAPS endpoints
    * Deploy the modified info.plist file to devices as a managed preference list through your MDM
* Deploy the pkg-wrapped package through your preferred MDM

## Migrating from macOSLAPS
* Customize the info.plist file to your preferences
    * Copy info.plist, and edit the empty values to match your MDM bindings and CloudLAPS endpoints.
    * Set a fallback key in the plist for new installs or edge cases
* Deploy the pkg-wrapped package through your preferred MDM
* The pre-install script will take care of migrating from the old software:
    * Checks for existing installations of macOSLAPS.
    * If found, uses a command to output the current password to an encrypted file.
    * After installation, CloudLAPS will pick up the encrypted password, decrypt it in memory and use it for first rotation.
    * The encrypted file is deleted after the first run.

## Contributing
Maintainers are accepting patches and contributions to this project.
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on submitting contributions to this project.

## Copyright
Copyright 2025 SAS Institute Inc., Cary, NC USA.

This project is licensed under the [Apache 2.0 License](LICENSE).

This work is based in part on [CloudLAPS](https://github.com/MSEndpointMgr/CloudLAPS) (Copyright 2021 MSEndpointMgr, MIT License) and [macOSLAPS](https://github.com/joshua-d-miller/macOSLAPS) (Copyright 2021 Joshua D. Miller, MIT License)

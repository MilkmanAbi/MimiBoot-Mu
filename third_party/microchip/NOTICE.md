# Microchip SAM D register headers

`samd21/include` and `samd51/include` hold three files each from Microchip's
SAM D21 / D51 device family packs (via github.com/hathach/microchip_driver,
as TinyUSB fetches them), unmodified:

- `component/usb.h`: the USB peripheral's register layout
- `component/nvmctrl.h`: the NVM controller, for the USB pad calibration fuses
- `instance/usb.h`: the USB instance

Copyright (c) Microchip Technology Inc., licensed under the Apache License,
Version 2.0 (SPDX-License-Identifier: Apache-2.0; the notice is at the top of
each file). The rest of a device header that TinyUSB's SAM D driver needs (IRQ
numbers, base addresses) is in `port/samd/usb/sam.h`, written for MimiBoot.

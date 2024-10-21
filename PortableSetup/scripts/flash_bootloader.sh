#!/usr/bin/env bash

JLinkExe -device nRF52840_xxAA -speed 4000 -if swd -autoconnect 1 -NoGui 1 -CommanderScript ./bootloader.jlink 

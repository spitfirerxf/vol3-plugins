# vol3-plugins
Collection of my volatility3 plugins

## November 2023
Writeups: https://medium.com/@rifqiaramadhan/volatility-3-plugin-kusertime-notepad-sticky-evtxlog-f0e8739eee55
### notepad.py
Plugin to determine the approximate content of an unsaved Notepad text based on biggest VAD content that Notepad allocates.
### kusertime.py
Plugin to determine the approximate uptime of a machine
### sticky.py
Plugin to extract the content for Sticky Notes on both Win10 and Win7
### evtxlog.py
Plugin to extract the extractable EVTX files and spit it out to console (very verbose, immediately pipe it to a file to ease investigation)

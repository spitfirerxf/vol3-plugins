# vol3-plugins
Collection of my volatility3 plugins

# How to use
- Install Volatility 3
- Copy the files to ./volatility3/plugins/windows (I currently am not working on Linux plugins)
- Install dependencies (check with `-v` when starting up `volatility3`)
- Done!


## November 2023
All Windows plugins.

Writeups: https://medium.com/@rifqiaramadhan/volatility-3-plugin-kusertime-notepad-sticky-evtxlog-f0e8739eee55

### notepad.py
Plugin to determine the approximate content of an unsaved Notepad text based on biggest VAD content that Notepad allocates.
### kusertime.py
Plugin to determine the approximate uptime of a machine
### sticky.py
Plugin to extract the content for Sticky Notes on both Win10 and Win7 (Note: not always working, depends on whether the machine cached the sticky note file or not)
### evtxlog.py
Plugin to extract the extractable EVTX files and spit it out to console (very verbose, immediately pipe it to a file to ease investigation)

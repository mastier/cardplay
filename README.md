### Why ?

I needed simple tool for testing and learning the Mifare and generally ISO14443A/B cards protocol for my thesis. I was inspired by [RFIDiot](https://github.com/AdamLaurie/RFIDIOt).

However this one has very nice advantage it will not let you screw the AC bits, so making the card useless in result.
It can import data to write from _yaml_,_csv_ or purely binary file (usually for previously exported). 


### Requirements

All needed requirements are in `requirements.txt` for your convience when using pip. Just use _pip install -r requirements.txt_.
Beside you need PCSCd daemon and libraries. On deb-based systems you just need to: `apt-get install pcscd libpcsclite-dev libnfc`

### Licensing

Enclosed in file.

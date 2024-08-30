# FortilogDecoder
Script to decode FortiNet logfiles as described in our blog post at https://cyber.wtf/2024/08/30/parsing-fortinet-binary-firewall-logs/.

Usually these FortiNet logfiles are named like elog/tlog.1706323123.log.gz or .zst

These kind of files are gz/z compressed. After decompression you should see a file partly readable beginning with 0xECCF or 0xAA01.

## Dependencies
pip install zstandard

## Usage
Decode single file, prints logs to stdout and errors/debug to fortilog_decoder.log:

`python fortilog_decoder.py logfile.log(.gz|.zst)`

Decode all files in source directory to existing target directory, prints errors/debug to stdout:

`python fortilog_decoder.py sourcedir targetdir`
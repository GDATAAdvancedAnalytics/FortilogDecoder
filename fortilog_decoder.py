#!/usr/bin/env python
"""
Script to decode FortiNet logfiles. Usually these files are named like elog/tlog.1706323123.log.gz or .zst
These kind of files are gz/z compressed. After decompression you should see a file partly readable beginning with 0xECCF or 0xAA01.

Dependencies
pip install zstandard

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.

"""

__author__ = "G DATA Advanced Analytics"
__date__ = "2024/08/28"
__version__ = "1.2"


import lz4.block
import lz4.frame
import sys
import os 
import gzip
import zstandard as zstd
import struct

debug = False
gz_output_file = False #if the target file should be gz compressed


magic = b'\xEC\xCF'
tlc_magic = b'\xAA\x01'
tlc_fields = ["","devid","devname","vdom","devtype","logtype","tmzone","fazid","srcip","unused?","unused?","num-logs","unzip-len","incr-zip","unzip-len-p","prefix","zbuf","logs"]

DCTX = zstd.ZstdDecompressor(max_window_size=2**31)
file_ptr_pos = 0



def process_dir(sourcedir,targetdir):
    """
    Traverses the sourcedir and opens similar files in targetdir for writing
    """
    try:
        with os.scandir(sourcedir) as src:
            for srcfile in src:
                if gz_output_file:
                    tfile = os.path.join(targetdir,f"{srcfile.name}.csv.gz")
                    if os.path.exists(tfile):
                        output_info(f"Skipped {srcfile.path} - already exists in destination",None,False)
                        continue
                    t = gzip.open(tfile,"w")
                else:
                    tfile = os.path.join(targetdir,f"{srcfile.name}.csv")
                    if os.path.exists(tfile):
                        output_info(f"Skipped {srcfile.path} - already exists in destination",None,False)
                        continue                
                    t = open(tfile,"wb")
                process_file(srcfile.path,t)
                t.close()
        src.close()
    except (Exception, KeyboardInterrupt) as e:
        if "t" in locals() and t and not t.closed:
            t.close()
        os.remove(tfile)
        output_info(f"Deleted last processed and maybe incomplete file {tfile} due to an unexpected exit",None,False)

def process_file(sourcefile,outstream):
    """
    Calls the decode function for each sourcefile and writes to outstream
    """
    try:
        if sourcefile.endswith(".gz"):
            s = gzip.open(sourcefile)
        elif sourcefile.endswith(".zst"):
            s = zstd.open(sourcefile,"rb",dctx=DCTX)
        else:
            raise Exception()
        decode_llogv5(s,sourcefile,outstream)
        s.close()
    except Exception as e:
        output_info(f"Skipped {sourcefile} - failed to open file, not a gz/zst file?",outstream,False)


def decode_llogv5(instream,sourcefile,outstream):
    """
    Function to decode a FortiNet logfile
    There are two different types within which are distinguished by magic bytes
    """
    file_ptr_pos = 0
    logentries = 0
    while (True):
        file_ptr_pos = instream.tell()
        logtype = instream.read(2)

        if logtype == magic:
            '''
            Each entry holds some additional data which is ignored. You may want to use these:
            In the header:
            timestamp = int.from_bytes(head[14:18],"big") eg. 1707916812
            In the body:
            devid = body[0:ldevid].decode("utf-8") eg. FG200FT1234
            devname = body[ldevid:ldevid+ldevname].decode("utf-8") eg. fa123
            vdom = body[ldevid+ldevname:ldevid+ldevname+lvdom].decode("utf-8") eg. root
            '''            
            output_info(f"Found lz4 entry at file offset {file_ptr_pos}",outstream,True)
            #1st variable part
            head = instream.read(16)
            flag = (head[0]>>2)&1
            ldevid = head[3]
            ldevname = head[4]
            lvdom = head[5]
            entrycount = int.from_bytes(head[6:8],"big")
            output_info(f"Entry holds {entrycount} logs",outstream,True)
            lentrycounts = entrycount * 2 
            lsomething = lentrycounts if flag else 0 #the twice thing, eg 8 zero padding bytes if flag true
            lcompressed = int.from_bytes(head[8:10],"big")
            ldecompressed = int.from_bytes(head[10:12],"big")
            lascii = ldevid+ldevname+lvdom
            body = instream.read(lascii+lentrycounts+lsomething+lcompressed)
            compressed_from = lascii+lentrycounts+lsomething
            entrieslengths = body[lascii:lascii+lentrycounts]
            compressed_to = compressed_from + lcompressed
            compressed = body[compressed_from:compressed_to]
            try:
                decompressed = lz4.block.decompress(compressed,ldecompressed+1)
                entries = []
                if entrycount > 1:
                    pointer = 0
                    for no in range(0,lentrycounts,2):
                        l = int.from_bytes(entrieslengths[no:no+2],"big")
                        entries.append(decompressed[pointer:pointer+l])
                        pointer += l
                elif entrycount == 1:
                    entries.append(decompressed)
                logentries+=len(entries)
                output_logs(outstream,entries)
            except Exception as e:
                output_info(f"Error: Skipped entry at offset {file_ptr_pos} in {instream.name} - LZ4 decompression failed",outstream,False)
                continue
            #2nd variable part, skip
            head2 = instream.read(2)
            body2 = int.from_bytes(head2,"little")
            instream.read(body2)
       
        elif logtype == tlc_magic:
            '''
            This is another type of embedded logs, which body is decoded in parse_tlc
            '''               
            output_info(f"Found tlc entry at file offset {file_ptr_pos}",outstream,True)
            instream.read(2)
            lbody = int.from_bytes(instream.read(4),"big")
            body = instream.read(lbody-8)
            tlc = parse_tlc(body,outstream,instream)
            entries = []
            for raw_entry in tlc.split(b"\x00"): #entries within tlc type are seperated by \x00
                
                entry = bytearray(map(ord,"date=")) #in front of each log we discard the substring logver=0702071577 <n>
                entryparts = raw_entry.split(entry)
                if len(entryparts) != 2:
                    continue
                entry.extend(entryparts[1])
                entries.append(entry)
            logentries+=len(entries)
            output_info(f"Decoded {len(entries)} logs from tlc entry",outstream,True)
            output_logs(outstream,entries)
        elif logtype == b'\x00\x00' or logtype == b'\x00': #pre-allocated space in live tlog.log.gz
            continue
        elif len(logtype) > 0: #data read but magic doesnt match
            output_info(f"Failed to decode file {sourcefile} - unknown header {logtype} at file offset {file_ptr_pos}, not a FortiNet logfile?",outstream,False)
            break
        else: #EOF
            output_info(f"Done {sourcefile} {logentries} logs",outstream,False)
            break


def parse_tlc(body,instream,outstream):
    '''
    This parses an entry of type tlc.
    Each entry holds several logs and fields like devid, timezone, srcip etc. We ommit those fields because these are additionally in the log entries themselves
    '''
    pointer = 0
    lunzipped = 0
    while pointer < len(body):
        typehigh = body[pointer] >> 4
        typelow = body[pointer] & 0x0F
        pointer+=1
        fieldid = body[pointer]
        pointer +=1
        if 0 <= typehigh <= 2:
            if typehigh == 0:
                larray = body[pointer]
                pointer +=1
            elif typehigh == 1:
                larray = struct.unpack_from(">h",body,pointer)[0]
                pointer +=2
            else:
                larray = struct.unpack_from(">I",body,pointer)[0]
                pointer +=4
            array = body[pointer:pointer+larray]
            pointer += larray
        elif typehigh == 3:
            value = body[pointer]
            pointer +=1
        elif typehigh == 4:
            value = struct.unpack_from(">h",body,pointer)[0]
            pointer += 2
        elif typehigh == 5:
            value = struct.unpack_from(">i",body,pointer)[0]
            pointer += 4
        elif typehigh == 6:
            value = struct.unpack_from(">l",body,pointer)[0]
            pointer += 8
        elif typehigh == 7:
            vala, valb = struct.unpack_from(">qq",body,pointer)
            value = (vala << 64) | valb
            pointer += 16

        if tlc_fields[fieldid] == "unzip-len":
            lunzipped = value
        elif tlc_fields[fieldid] == "num-logs":
            output_info(f"TLC entry holds {value} log entries", outstream,True)
        elif tlc_fields[fieldid] == "zbuf":
            if lunzipped == 0 or len(array) == 0:
                output_info(f"Error: Could not decode tlc entry at offset {file_ptr_pos} in {instream.name}",outstream,False)
                return bytearray()
            try:
                decompressed = lz4.frame.decompress(array,lunzipped)
            except:
                output_info(f"Error: Skipped entry at offset {file_ptr_pos} in {instream.name} - LZ4 decompression failed",outstream,False)
                return bytearray()

            return decompressed

    return bytearray()


def output_info(fstr,outstream,typedebug):
    '''
    This outputs messages to varying targets
    '''
    global log_ptr
    if typedebug and not debug:
        return
    if outstream is sys.stdout: #write to logfile if stdout is used for log output
        log_ptr.write(fstr+"\n")
    else:
        print(fstr)


def output_logs(outstream,entrieslist):
    '''
    This outputs the decoded logs to varying targets
    '''
    if outstream is sys.stdout:
        for entry in entrieslist:
            outstream.write(entry.decode(outstream.encoding)+"\n")
    else:
        for entry in entrieslist:
            outstream.write(entry+b"\x0a")


if __name__ == "__main__":
    # decode single file to stdout
    if len(sys.argv) == 2 and os.path.isfile(sys.argv[1]):
        log_ptr = open("fortilog_decoder.log","w")
        process_file(sys.argv[1],sys.stdout)
        log_ptr.close()
    # decode directory
    elif len(sys.argv) == 3 and os.path.isdir(sys.argv[1]) and os.path.isdir(sys.argv[2]):
        process_dir(sys.argv[1],sys.argv[2])
    # usage
    else:
        print(f"Usage:\nDecode single file, prints logs to stdout and errors/debug to fortilog_decoder.log:\n{os.path.basename(__file__)} logfile.log.gz|.zst\n\nDecode all files in source directory to existing target directory, prints errors/debug to stdout:\n{os.path.basename(__file__)} sourcedir targetdir")
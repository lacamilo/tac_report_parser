#!/usr/bin/env python3

import re
import math
import sys
import ctypes

__author__ = "Luiz Camilo"
__version__ = "0.0.3"
__maintainer__ = "Luiz Camilo"
__email__ = "lcamilo@fortinet.com"
__status__ = "Unstable"

# compile : pyinstaller -F -n tac_report_parser.exe main.py

# Enable Windows CMD color mode
kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

# Variables definitions - should move to a class later 
#file_in = input ("Where the file is located? :")
print("Script under development... \nAuthor: Luiz Camilo - lcamilo@fortinet.com\n")

#command_block = input ("Type the command block you need ex: diagnose ip address list :")
#vstring = command_block

#file_in = "FG200FT920905464_debug.log"
#print('Argument List:', str(sys.argv))
try:
    file_in = str(sys.argv[1])
except:
    print("Usage: fileparser.py filename <= argument missing\n")
    sys.exit(2)
#file_in = input ("Type the debug.log file path/name:")
file_out = "debug_parsed.log"

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    red     = '\033[31m'
    green   = '\033[32m'
    yellow  = '\033[33m'
    blue    = '\033[34m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'
    blink = '\033[5m'

def color(text, color):
    text = str(text)
    if color == "red":
        return bcolors.red + text + bcolors.ENDC
    if color == "green":
        return bcolors.green + text + bcolors.ENDC
    if color == "blue":
        return bcolors.blue + text + bcolors.ENDC
    if color == "yellow":
        return bcolors.yellow + text + bcolors.ENDC

class parse:
    def __init__(self, device, log):
        self.device = device
        self.log    = None

    def key_lines(vtext):
        # this parser would find lines starting with ###
        # It receives 1 line at a time and returns it if the string was found 
        # It returns None if the string was not found.
        parser1 = re.compile(r"[\#]{3}")
        if re.match(parser1,vtext):
            return(vtext.strip())

    def get_cmd_index(file):
        # this parser deals with the file stream
        #populate a dictionary with the commands and line numbers
        command_index = {}
        with open(file_in, "r") as fp:
            for count, line in enumerate(fp):
                empty = None
                if not empty == parse.key_lines(line):
                    #print(count+1, ' - ', parse.key_lines(line))
                    # store found values on a dictionary
                    command_index[count+1] = {"command": parse.key_lines(line)}
        # returns a dictionary with found items 
        return(command_index)

    def get_cmd_block(vstring,command_index,file):
        # this function requires the output from get_cmd_index 
        # it reads the dictionary and finds the start and end of a given block. 
        # This block finds the starting and end line of the desired command in the file 
        line = 0
        vstart_line = 0
        vend_line = 0
        for index, value in enumerate(command_index.items()):
            #print(value)
            # find starting line 
            if vstring in str(value):
                #print("start line: ", value[0])
                #print("start line: ", index,value)
                line = 1
                vstart_line = value[0]
                continue
            # find the next line 
            if line == 1:
                #print("end line: ", index,value)
                vend_line = value[0]
                break
                # command_index.items - returns full line with index, command and #### string 
                # command_index.values - returns command : #### string
                # command_index.keys - will return the line number index number 
                # dir(object) list attributes 
        # this block will process the starting and end lines from the text file. 
        # this is where we should parse further 
        block_index = {}
        with open(file, "r") as fp:
            for count, line in enumerate(fp):
                #print(count)
                if vstart_line:
                    if count >= vstart_line-1 and count < vend_line-1:
                        #print(line.strip())
                        block_index[count] = {line.strip()}
                else:
                    return(None)
                    break
        # returns a dictionary with the lines from start and end of a command. 
        return(block_index)

        #print(block_index,end='\n')
        #with open(file, "r") as fp:
        #    content = fp.readlines()
        #    print(content[24857-24866],end='\n')
        #    #print(content[vstart_line-vend_line],end='\n')
        #    print(dir(fp))

    def convert_size(size_bytes):
        # convert decimal Bytes in Gigabytes.
        # Adjust input to Bytes always
        if size_bytes == 0:
            return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 0)
        return "%s %s" % (s, size_name[i])

    def get_percentage(part, whole):
        Percentage = 100 * float(part)/float(whole)
        # return(str(round(Percentage,0)) + " %") # return string 
        return(round(Percentage, 0)) # return int

    def regexparser(vregex,block_index):
        vaction = None
        vstring_found = ""
        # This function will return the matched lines
        for command in vregex.items():
            #print("command branch", command[1][0])
            #print(command[1][1])
            #receive the query
            vregex = re.compile((command[1][1]))
            #isolate queries with instructions
            if len(command[1]) == 3:
                vaction = command[1][2]
                #print(vaction)
            #receive the entire block of text lines
            #find a way to only update the current block if the command branch changes.
            vblock = parse.get_cmd_block(command[1][0],block_index,file_in)
            if vblock:
                #vfound = re.search(vregex,vblock.values())
                #print(vfound)
                for value in enumerate(vblock.values()):
                    #print(*value[1])
                    if re.search(vregex,*value[1]):
                    #   print(command[1][1].group(1))
                        vstring_found = re.search(vregex,*value[1]).group()
                        #print(vstring_found)
                        if vaction != None:
                           print(vstring_found," - ",vaction)
                        else:
                           print(vstring_found)
                    #else:
                    #    pass
            else:
                print("command not fount in debug_log file :",command[1][0])
                next
            vaction = None
    def crashlog(block_index):
        # could only consider timestamps in the last 30 days. - Idea 
        parser1 = re.compile(r"([0-9]{4}\-[0-9]{2}\-[0-9]{2}\s[0-9]{2}\:[0-9]{2}\:[0-9]{2})") # find timestamp
        parser2 = re.compile(r"\s(\w+)\s(previously crashed)\s(\d{2}|\d{1})\stimes")
        parser3 = re.compile(r"(\*){3}\s(signal)\s(\d{1}|\d{2})\s\((\w+\s\w+|\w+)\)\s(received)\s(\*{3})")
        #parser4 = re.compile(r"((Forti)(Gate|Wifi)\-\d*(C|D|E|F|G)\s(v\d\.\d\.\d))") # extract firmware version for further match
        parser5 = re.compile(r"application\s(\w+)")
        parser6 = re.compile(r'conserve=(\w+)\stotal=\"(\d+)\s\w+\"\sused=\"(\d+)\s\w+\"\sred=\"(\d+)\s\w+\"')
        vcrashcount = 0
        vapplication = ""
        vsignal = 0
        appcrashes = {}
        timestamp = "No Crash Dump Found in report"
        line = 0
        vconservecount = 0
        vconservetimestamp = ""
        for value in enumerate(block_index.values()):
            #print(*value[1])
            line = line + 1
            # Find Crashes
            if re.search(parser2,*value[1]):
                #vcrashcount = vcrashcount + int(re.search(parser2,*value[1]).group(3)) #sum of existing data
                vcrashcount = vcrashcount + 1 # sum of occurrences
                #print("line found! : ", *value[1])
                if re.search(parser1,*value[1]):
                    # find timestamp of when it happened
                    timestamp = re.search(parser1,*value[1]).group(1)
                    #print("line found! : ", timestamp)
            # print(*value[1])
            # print(re.search(parser5,*value[1]).group(1))
            if re.search(parser5,*value[1]):
                vapplication = re.search(parser5,*value[1]).group(1)
                #print("application :",re.search(parser5,*value[1]).group(1))
            if re.search(parser3,*value[1]):
                vsignal = re.search(parser3,*value[1]).group(3)
                #print("signal code :", re.search(parser3,*value[1]).group(3))
            if appcrashes:
                # Dictionary not empty - update
                if vapplication in appcrashes.keys():
                    appcrashes.update({vapplication: [vsignal, int(appcrashes.get(vapplication)[1])+1]})
                    #print(appcrashes)
                    #print(appcrashes.get(vapplication))
                    if vsignal in appcrashes.items():
                        print(appcrashes.get(vapplication))
                else:
                    appcrashes[vapplication] = [vsignal, 1]
            else:
                # Dictionary empty - initialize
                appcrashes[vapplication] = [vsignal, 1]
            #break
            if re.search(parser6,*value[1]):
                if re.search(parser6,*value[1]).group(1) == "on":
                    vconservecount = vconservecount +1
                    vconservetimestamp = re.search(parser1,*value[1]).group(1)

        print("Crash tracker lines found => previously crashed", vcrashcount, "times.")
        print("Found ",vconservecount, "Conserve mode events - Last one was on :", vconservetimestamp)

        for value in appcrashes.items():
            if value[0]:
                #print(appcrashes.values())
                #print(appcrashes.keys())
                #print(appcrashes.items())
                #print(appcrashes[''])
                print("process\t", value[0], " \tcrashed", value[1][1], "\ttimes with exit code\t",value[1][0])

        print("last crash was on :", timestamp, )
        for value in enumerate(block_index.values()):
            #read it again and find last crash lines
            if re.search(timestamp,*value[1]):
                print(*value[1])
                #continue
        print("\n")

    def syshastatus(block_index):
        if block_index:
            parser1 = re.compile(r"(\w+)\:\s+(Primary),\sserialno_prio") # Find Primary unit
            parser2 = re.compile(r"(\w+)\:\s+(Secondary),\sserialno_prio")
            vprimary = ""
            vsecondary = ""
            for value in enumerate(block_index.values()):
                if re.search(parser1,*value[1]):
                    vprimary = re.search(parser1,*value[1]).group(1)
                if re.search(parser2,*value[1]):
                    vsecondary = re.search(parser2,*value[1]).group(1)

            # Do nothing for now. I'll find a use case for this output
            #print(vprimary)
            #print(vsecondary)
    def performancestatus(block_index):
        if block_index:
            # could warn sessions per device model - idea 
            parser1 = re.compile(r"(Memory\:\s\d*k\stotal)\,\s(\d*k\sused\s\(\d{2}\.\d\%\))\,\s(\d*k\sfree\s\(\d{2}\.\d\%\))\,\s(\d*k\sfreeable\s\((\d{2}|\d{1})\.\d\%\))") # group3 memory used
            parser2 = re.compile(r"(\d{1}|\d{2})\.(\d{1}|\d{2})") # extract amount of memory from a capture group
            parser3 = re.compile(r"(Uptime\:\s(\d{2}|\d{1})\sdays\,\s\s(\d{2}|\d{1})\shours\,\s\s(\d{2}|\d{1})\sminutes)")

            # extract low free memory 
            vmemoryline = None
            vmemoryfree = None
            for value in enumerate(block_index.values()):
                #print(*value[1])
                if re.search(parser1,*value[1]):
                    vmemoryline = re.search(parser1,*value[1]).group(3)
                    break

            if vmemoryline != None:
                # extract free memory
                vmemoryfree = re.search(parser2,vmemoryline).group()
                # vmemoryfree[1] = result
                # vmemoryfree.span() returns a tuple containing the start-, and end positions of the match.
                # vmemoryfree.string returns the string passed into the function
                # vmemoryfree.group() returns the part of the string where there was a match and converts it to string

                print("Amount of Memory free :", vmemoryfree)
                if float(vmemoryfree) <= 25.0:
                    print("High Memory usage :", color(100.0-(float(vmemoryfree)),'yellow'))
                    pass
                #print(type(vmemoryfree))#
    def hardwarememory(block_index):
        # Function will return warnings based on memory usage. 
        parser1 = re.compile("MemTotal\:\s*(\d*)")
        parser2 = re.compile("MemFree\:\s*(\d*)")
        parser3 = re.compile("Dirty\:\s*(\d*)") # Ideal always zero
        parser4 = re.compile("Slab\:\s*(\d*)") # Too many simultaneous sessions ?
        parser5 = re.compile("Shmem\:\s*(\d*)") # proxy conserve mode - WAD, IPS High memory usage.
        parser6 = re.compile("^Cached:\s*(\d*)")
        for value in enumerate(block_index.values()):
            #print(*value[1])
            if re.search(parser1,*value[1]):
                vtotalmem_raw = int(re.search(parser1,*value[1]).group(1))
                vtotalmem = parse.convert_size(int(re.search(parser1,*value[1]).group(1))*1024) #convert Kb kiloBytes to Bytes
                print("Total Memory\t: ", vtotalmem)
            if re.search(parser6,*value[1]):
                # this needs adjust 
                vtotalmem_raw = int(re.search(parser6,*value[1]).group(1))
                vtotalmem = parse.convert_size(int(re.search(parser6,*value[1]).group(1))*1024) #convert Kb kiloBytes to Bytes
                print("Cached\t\t: ", vtotalmem, "\t- node.js is known to spike cache")
            if re.search(parser2,*value[1]):
                vfreemem_raw = int(re.search(parser2,*value[1]).group(1))
                vfreemem_per = parse.get_percentage(vfreemem_raw,vtotalmem_raw)
                vfreemem = parse.convert_size(int(re.search(parser2,*value[1]).group(1))*1024)
                if vfreemem_per <= 18.0:
                    print("Free Memory\t: ", vfreemem, "\t- ", color(str(vfreemem_per)+" %",'yellow'))
                elif vfreemem_per <= 12.0:
                    print("Free Memory\t: ", vfreemem, "\t- ", color(str(vfreemem_per)+" %",'red'), "<= Under Conserve mode Now")
                elif vfreemem_per >=18.1:
                    print("Free Memory\t: ", vfreemem, "\t- ", vfreemem_per, " %")
            if re.search(parser3,*value[1]):
                vdirtymem_raw = int(re.search(parser3,*value[1]).group(1))
                vdirtymem = parse.convert_size(int(re.search(parser3,*value[1]).group(1))*1024)
                print("Dirty Memory\t: ", vdirtymem, "\t- pending changes to be saved to disk - closer to zero, the better")
            if re.search(parser4,*value[1]):
                vslabmem_raw = int(re.search(parser4,*value[1]).group(1))
                vslabmem = parse.convert_size(int(re.search(parser4,*value[1]).group(1))*1024)
                print("Slab Memory\t: ", vslabmem)
            if re.search(parser5,*value[1]):
                vshmem_raw = int(re.search(parser5,*value[1]).group(1))
                vshmem = parse.convert_size(int(re.search(parser5,*value[1]).group(1))*1024)
                print("Shared Memory\t: ", vshmem)
        print("\n")

    def systopall(block_index):
        if block_index:
            parser1 = re.compile(r"([a-z_A-Z]+)\s+(\d+)\s+([SRZD])\s([<|\s])\s+(\d\.\d)\s+(\d\.\d)\s+(\d)")
            processname = ""
            pidnumber = 0
            processtatus = ""
            highpriority = ""
            cpusage = 0.0
            memusage = 0.0
            cpuafinity = 0
            firstline = 0
            # detect 1st line and print it only if high values are found.
            for value in enumerate(block_index.values()):
                if re.search(parser1,*value[1]):
                    processname = re.search(parser1,*value[1]).group(1)
                    pidnumber = int(re.search(parser1,*value[1]).group(2))
                    processtatus = re.search(parser1,*value[1]).group(3)
                    highpriority = re.search(parser1,*value[1]).group(4)
                    cpusage = float(re.search(parser1,*value[1]).group(5))
                    memusage = float(re.search(parser1,*value[1]).group(6))
                    cpuafinity = int(re.search(parser1,*value[1]).group(7))
                    if cpusage >= 30.0:
                        if firstline == 0:
                            print("PID\tStatus\tCPU\tMEM\tName  \t\t\tAffinity")
                            firstline = 1
                        print(pidnumber,"\t",processtatus,"\t",cpusage,"\t",memusage,"\t",processname,"   \t\t",cpuafinity,"\t <= Possible High CPU Usage")
                    if memusage >= 3.0:
                        if firstline == 0:
                            print("PID\tStatus\tCPU\tMEM\tName  \t\t\tAffinity")
                            firstline = 1

                        print(pidnumber,"\t",processtatus,"\t",cpusage,"\t",memusage,"\t",processname,"   \t\t",cpuafinity,"\t <= Possible High Memory Usage")
            print("\n")
    def ipsanomalylist(block_index):
        if block_index:
            parser1 = re.compile(r'^id=(\w+)\s+ip\=(\d+.\d+.\d+.\d+)\sdos_id\=(\d)\sexp\=(\d+)\spps\=(\d+)\sfreq\=(\d+)')
            vcount = 0
            dosid = 0
            dosidcount = 0
            for value in enumerate(block_index.values()):
                if re.search(parser1, *value[1]):
                    dosid = re.search(parser1,*value[1]).group(3)
                    dosidcount = dosidcount+1
            if dosid != 0:
                print("DOS Policy id ",dosid," was found taking actions ", dosidcount," times")
                print("\n")
    def sysinfoslab(block_index):
        # Find high number of TCP and IP sessions exhausting memory . 
        print("\n")
    def autoupdateversions(block_index):
        # contract about to expire or expired 
        # Connectivity failures 
        print("\n")
    def gethardwarenic(block_index):
        if block_index:
            print(block_index.values())

def main():
    #
    # build a list with all commands from file 
    command_index = parse.get_cmd_index(file_in)
    #print(command_index.items(),end="\n")

    #Retrieve static information
    vregex = {
            1: ["get system status",r"Version:\s(.*)"],
            2: ["get system status",r"Firmware Signature\:\s(certified)"],
            3: ["get system status",r"Serial-Number:\s(.*)"],
            4: ["get system status",r"Current\sHA\smode\:\s(a-p|a-a)\,\s(\w+)"],
            5: ["get system status",r"Hostname:\s(.*)"],
            6: ["get system status",r"Last reboot reason:\s(.*)"],
            7: ["get system status",r"Cluster uptime:\s(.*)"],
            8: ["get system performance status",r"(Uptime\:\s(\d{2}|\d{1})\sdays\,\s\s(\d{2}|\d{1})\shours\,\s\s(\d{2}|\d{1})\sminutes)"],
            9: ["show full-configuration system global",r"set\sadmin-maintainer\s(disable)","Maintainer Disabled"],
            10: ["show full-configuration system global",r"set\sadmin-sport\s(?!443).*","Custom Admin Port"],
            11: ["show full-configuration system global",r"set\sdaily-restart\s(enable)"],
            12: ["show full-configuration system global",r"set\sipsec-asic-offload\s(disable)","Non Default Value"],
            13: ["show full-configuration system global",r"set\stcp-halfclose-timer\s((?!120).*)","Non Default Value"],
            14: ["show full-configuration system global",r"set\stcp-halfopen-timer\s((?!10).*)","Non Default Value"],
            15: ["show full-configuration system global",r"set\stcp-timewait-timer\s((?!1).*)","Non Default Value"],
            16: ["show full-configuration system settings",r"set\sasymroute\s(enable)","Non Default Value"],
            17: ["show full-configuration system settings",r"set\sdefault-voip-alg-mode\s((?!proxy-based).*)","Non Default Value"],
            18: ["diagnose sys session stat",r"(clash\=(\d*))","<= Session clashes"],
            19: ["diagnose sys session stat",r"memory_tension_drop\=(\d*)","<= Memory Tension Drops"],

            20: ["diagnose test update info",r"account_id\=\[(\w*\@\w*\.\w*)\]\scompany\=\[(.*?)\]"],
            21: ["diagnose test update info",r"User\sID\:\s(.*)"]
            }
    parse.regexparser(vregex,command_index)

    # Retrieve information that needs to be parsed
    parse.performancestatus(parse.get_cmd_block("performance status",command_index,file_in))
    parse.hardwarememory(parse.get_cmd_block("get hardware memory",command_index,file_in))
    parse.crashlog(parse.get_cmd_block("crashlog read",command_index,file_in))
    parse.systopall(parse.get_cmd_block("diagnose sys top-all 1 100 1",command_index,file_in))
    parse.ipsanomalylist(parse.get_cmd_block("diagnose ips anomaly list", command_index, file_in))
    #parse.syshastatus(parse.get_cmd_block("diagnose sys ha status", command_index, file_in))
    parse.gethardwarenic(parse.get_cmd_block("get hardware nic", command_index, file_in))

    # print(vregex[1][1])
    # for value in enumerate(vregex.items()): 
        # print(value[1])

    #### Debugs ####
    #print(color('hello', 'red'), color('world', 'green'))

    # Debug - start here 
    # finds a specific block of command
    #vstring = "performance status"
    #block_index = parse.get_cmd_block(vstring,command_index,file_in)
        # confirm the results:
    #for value in enumerate(block_index.values()):
    #    print(*value[1])
    #print(type(value))

if __name__ == "__main__":
    #open the file
    #file1 = open(file_in,"r")
    main()
    #input("Press Enter to continue...")

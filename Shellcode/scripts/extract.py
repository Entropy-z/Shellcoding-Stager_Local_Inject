#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import pefile
import argparse

##
## parse specified executable file and
## save .text section shellcode into a file
##
def main():
    try:
        ##
        ## parse args
        ## 
        parser = argparse.ArgumentParser( description = 'Extracts shellcode from a PE.' )
        parser.add_argument( '-f', required = True, help = 'Path to the source executable', type = str )
        parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str )
        option = parser.parse_args()

        ##
        ## open exe file and output bin file
        ## 
        PeExe = pefile.PE( option.f )
        file = open( option.o, 'wb+' )

        ##
        ## get .text section data
        ##
        for section in PeExe.sections:

            ##
            ## check if it's .text section
            ##
            if section.Name.replace( b'\x00', b'' ).decode( 'utf-8' ) == ".text":
                
                print( f"[*] found shellcode [size: {len(section.get_data())} bytes]" )

                ##
                ## write .text section code into file
                ##
                file.write( section.get_data() )

                break

        ##
        ## close shellcode file
        ##
        file.close()

    except Exception as e:
        print( '[!] error: {}'.format( e ) )

    return

if __name__ in '__main__':
    main()

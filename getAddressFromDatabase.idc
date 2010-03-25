//
//      Sample IDC program to automate IDA Pro.
//
//      IDA Pro can be run from the command line in the
//      batch (non-interactive) mode.
//
//      If IDA is started with
//
//              idag -A -Sanalysis.idc file
//
//      then this IDC file will be executed. It performs the following:
//
//        - the code segment is analyzed
//        - the output file is created
//        - IDA exits to OS
//
//      Feel free to modify this file as you wish
//      (or write your own script/plugin to automate IDA)
//
//      Since the script calls the Exit() function at the end,
//      it can be used in the batch files (use text mode idaw.exe)
//
//      NB: "idag -B file" is equivalent to the command line above
//

#include <idc.idc>
#include "address_finder.idc"

static main()
{
    auto Address,out;
    Address = getAddressFromFile("addressFile.txt");
    if(Address == -1){
        Exit(1);
    }
    out = fopen("outAddress", "a");
    fprintf(out, "0x%08x\n", Address);
    fclose(out);
    Exit(0);
}
#include <idc.idc>

static getOccurances(search)
{
    auto location,location2;
    location = FindBinary(0,SEARCH_DOWN, search);
    //Message("%x\n", location);
    location2 = FindBinary(location+1,SEARCH_DOWN,search);
    //Message("%x\n", location2);
    if(location2 == BADADDR){
    //    Message("Only Occurance\n");
        return(location);
    }
    return(BADADDR);
}

static getAddressFromSearchString(sstring){
    auto searchString,spaceLoc,byteToGet,foundLocation;
    spaceLoc = strstr(sstring, ";");
    searchString = substr(sstring, 0,spaceLoc);
    byteToGet = atol(substr(sstring,spaceLoc+1,-1));
    foundLocation = getOccurances(searchString);
    if(foundLocation != -1){ // has 1 unique occurance
        return(Dword(foundLocation+byteToGet));
    }
    else{
        return(-1);
    }
    //Message("%s:%d:%d\n", searchString,byteToGet,spaceLoc);
}
static getAddressFromFile(file){
    auto fileHandle,line;
    fileHandle = fopen(file,"r");
    line = readstr(fileHandle);
    while(line != -1){
        auto location;
        location = getAddressFromSearchString(substr(line,0,strlen(line)));
        if(location != -1){
            return(location);
        }
        line = readstr(fileHandle);
    }
    close(fileHandle);
    return(-1);
}
static main(){
    auto filename;
    filename = AskFile(0,"*.*","File of patterns to search");
    Message("%x",getAddressFromFile(filename));
}
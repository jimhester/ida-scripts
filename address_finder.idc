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
    auto searchString,sepLoc,sepLoc2,byteToGet,shiftAmount,foundLocation;
    sepLoc = strstr(sstring, ";");
    sepLoc2 = strstr(substr(sstring,sepLoc+1,-1),";")+sepLoc;
    searchString = substr(sstring, 0,sepLoc);
    byteToGet = atol(substr(sstring,sepLoc+1,sepLoc2+1));
    shiftAmount = atol(substr(sstring,sepLoc2+2,-1));
    foundLocation = getOccurances(searchString);
    //Message("%s:%s:%s\n", searchString,substr(sstring,sepLoc+1,sepLoc2+1),substr(sstring,sepLoc2+2,-1));
    if(foundLocation != -1){ // has 1 unique occurance
        return(Dword(foundLocation+byteToGet)+shiftAmount);
    }
    else{
        return(-1);
    }
}
static getAddressFromFile(file){
    auto fileHandle,line;
    fileHandle = fopen(file,"r");
    line = readstr(fileHandle);
    while(line != -1){
        auto location;
        location = getAddressFromSearchString(substr(line,0,strlen(line)));
        if(location != -1){
            fclose(fileHandle);
            Message("%s: 0x%08x\n", file,location);
            return(location);
        }
        line = readstr(fileHandle);
    }
    fclose(fileHandle);
    Message("%s: 0x%08x\n", file,location);
    return(-1);
}
static findLastOccuranceOf(string,stringToFind)
{
    auto location, prevLocation,itr;
    prevLocation = 0;
    location = strstr(string,stringToFind);
    itr = 0;
    while(location != -1){ 
        prevLocation = location+prevLocation+itr;
        location = strstr(substr(string,prevLocation,-1),stringToFind);
        itr++;
    }
    return(prevLocation-1);
}
static processFile(openFilename,outFilename,writeMode){
    auto directory,line,fileHandle,outHandle,md5Hash;
    fileHandle = fopen(openFilename, "r");
    outHandle = fopen(outFilename,writeMode);
    md5Hash = GetInputMD5();
    fprintf(outHandle,"md5 %s\n", md5Hash);
    if(GetShortPrm(INF_FILETYPE) == FT_PE){ // windows get pe pe_timestamp
        auto current,exeHandle,pe_offset,pe_timestamp;
        current = GetInputFilePath();
        exeHandle = fopen(current, "rb");
        fseek(exeHandle, 0x3c, 0);
        pe_offset = readlong(exeHandle, 0);
        fseek(exeHandle, pe_offset + 0x8, 0);
        pe_timestamp = readlong(exeHandle, 0);
        fprintf(outHandle,"pe_timestamp %x\n", pe_timestamp);
        fclose(exeHandle);
    }
    line = readstr(fileHandle);
    while(line != -1 ){
        auto beginName,endName,name,address;
        beginName = findLastOccuranceOf(line,"\\");
        endName = strstr(line, "_patterns");
        name = substr(line,beginName,endName);
        address = getAddressFromFile(substr(line,0,strlen(line)-1));
        fprintf(outHandle,"%s 0x%08x\n", name,address);
        line=readstr(fileHandle);
    }
    fclose(fileHandle);
    fclose(outHandle);
}
static main(){
    if(AskYN(1,"Do you want to search for an address with patterns in a single file?")){
        auto filename;
        filename = AskFile(0,"*.*","File of patterns to search");
        Message("%x",getAddressFromFile(filename));
    }
    else{
        if(AskYN(1,"Do you want to search for all patterns in paths given by a file?")){
            auto openFilename, outFilename;
            openFilename = AskFile(0,"*.*", "File with pathnames for address files");
            outFilename = AskFile(1,"*.*", "Filename to save the addresses");
            processFile(openFilename, outFilename, "w");
        }
    }
}

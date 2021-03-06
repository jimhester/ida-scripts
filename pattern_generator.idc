#include <idc.idc>

static countSpaces(testString)
{
    auto location;
    auto currentString;
    auto count;
    count = 0;
    location = strstr(testString," ");
    currentString = testString;
    while(location != -1){
        count++;
        currentString = substr(currentString, location+1,-1);
        location = strstr(currentString," ");
    }
    return(count);
}
static getVarSize(opString)
{
    if(strstr(opString,"byte")){
        return(1);
    }
    if(strstr(opString,"word")){
        return(2);
    }
    if(strstr(opString,"dword")){
        return(4);
    }
    return(-1);
}

static getSearchString(start)
{
    auto end,i,startItr,hasMemoryLoc,searchString;
    auto firstOpType, secondOpType,firstOpStr,secondOpStr;
    
    
    hasMemoryLoc = 0;
    end = ItemSize(start);
    startItr = 1;
    
    firstOpType = GetOpType(start,0);
    firstOpStr = GetOpnd(start,0);
    secondOpType = GetOpType(start,1);
    secondOpStr = GetOpnd(start,1);
    searchString = form("%02x",Byte(start));
    if(firstOpType == 2 || strstr(firstOpStr,"offset") != -1){
        hasMemoryLoc = 1;
    }
    if(secondOpType == 2 || strstr(secondOpStr,"offset") != -1){
         hasMemoryLoc = 2;
    }
    
    if(hasMemoryLoc == 1){
        if(secondOpType == 1){
            startItr = end;
            for(i = 1; i < end-4;i++){
                searchString = searchString + " " + form("%02x",Byte(start+i));
            }
        }
        else{
            startItr = end-4;
            for(i = 1; i < startItr-4;i++){
                searchString = searchString + " " + form("%02x",Byte(start+i));
            }
        }
        searchString = searchString + " ? ? ? ?";
    }
    if(hasMemoryLoc == 2){
        end = end -4;
    }
    for(i = startItr;i < end;i++){
        searchString = searchString + " " + form("%02x",Byte(start+i));
    }
    if(hasMemoryLoc == 2){
        searchString = searchString + " ? ? ? ?";
    }
    //Message("%d %d %s\n", startItr, end,searchString);
    return(searchString);
}

static getOccurances(search)
{
    auto location,location2;
    location = FindBinary(0,SEARCH_DOWN, search);
    if(location == BADADDR){
        return(-1);
    }
    //Message("%x\n", location);
    location2 = FindBinary(location+1,SEARCH_DOWN,search);
    //Message("%x\n", location2);
    if(location2 == BADADDR){
    //    Message("Only Occurance\n");
        return(location);
    }
    return(-2);
}

static getSmallestSearchString(start)
{
    auto forward,reverse,revString,search,itr,value,searchOccurances;
    itr = 0;
    forward = NextHead(start,start+100);
    reverse = PrevHead(start,start-100);
    search = getSearchString(start);
    value = strstr(search,"?");
    searchOccurances = getOccurances(search);
    while(searchOccurances == -2 && itr < 20){
        if(itr % 2 == 0){
            revString = getSearchString(reverse);
            search = revString + " " + search;
            value = value + strlen(revString)+1;
            reverse = PrevHead(reverse, reverse-100);
        }
        else{
            search = search + " " + getSearchString(forward);
            forward = NextHead(forward, forward + 100);
        }
        searchOccurances = getOccurances(search);
        itr = itr + 1;
    }
    if(searchOccurances == -1){
        Message("Search string %s not found, something is wrong\n",search);
        return("");
    }
    return(form("%s\;%d",search,countSpaces(substr(search,0,value))));
}
static pattern_generator(start,filename,showFile,isVector){
    auto checkStart,searchString,arrayId,currXRef,arrayIndex,stringLength,hFile,itr,shiftAmount,xrefCutoff;
    xrefCutoff = 100; // make this higher if you want more xrefs
    shiftAmount = 0;
    hFile = fopen(filename, "wb");
    currXRef = DfirstB(start);
    if(GetShortPrm(INF_FILETYPE) == FT_PE && (isVector || currXRef == -1)){
        start = start+4;
        currXRef = DfirstB(start);
        if(currXRef == -1){
            return(-1);
        }
        shiftAmount = -4;
    }
    searchString = getSmallestSearchString(currXRef);
    fprintf(hFile,"%s;%d\r\n", searchString,shiftAmount);
    currXRef = DnextB(start,currXRef);
    Message("%d",1);
    itr = 2;
    while(currXRef != -1 && itr <= xrefCutoff){
        Message(",%d", itr);
        if(itr % 50 == 0){
            Message("\n");
        }
        searchString = getSmallestSearchString(currXRef);
        fprintf(hFile,"%s\;%d\r\n", searchString,shiftAmount);
        currXRef = DnextB(start,currXRef);
        itr=itr+1;
    }
    Message("\n");
    fclose(hFile);
    if(showFile){
        Exec("start notepad " + filename);
    }
}

static main(void){
    if(AskYN(1,"Do you want to search for patterns at the cursor location?")){
        auto start,szFilePath;
        start = ScreenEA();
        szFilePath = AskFile(1, "*.txt", "Select output dump file:");
        if(GetShortPrm(INF_FILETYPE) == FT_PE){ # only have to treat vectors different in windows
            pattern_generator(start,szFilePath,1,AskYN(1,"Is the address a vector?"));
        }
        else{
            pattern_generator(start,szFilePath,1,0);
        }
    }
    else{
        auto directory,openFilename,line,fileHandle,outHandle;
        directory = AskStr("C:\\", "Please enter a location to dump the files");
        openFilename = AskFile(0,"*.*", "File with addresses to generate patterns for");
        outHandle = fopen(directory + "\\filenames.txt","w");
        fileHandle = fopen(openFilename, "r");
        line = readstr(fileHandle);
        while(line != -1 ){
            auto addressName, address,spaceLoc,isVector;
            isVector = 0;
            if(strstr(line,"\*") != -1){
                Message("vector\n");
                line = substr(line,1,-1);
                isVector = 1;
            }
            spaceLoc = strstr(line," ");
            addressName = substr(line,0,spaceLoc);
            address = xtol(substr(line,spaceLoc+1,strlen(line)));
            if(addressName != "md5" && addressName != "pe_timestamp"){
                Message("Finding Patterns for for %s, at %x\n",addressName, address);
                fprintf(outHandle, "%s\n", directory + "\\" + addressName + "_patterns.txt");
                pattern_generator(address, directory + "\\" + addressName + "_patterns.txt",0,isVector);
                line=readstr(fileHandle);
            }
        }
        fclose(outHandle);
        fclose(openFilename);
    }
}

    //for(i = ScreenEA();
    //Warning("%d %d",GetOpType(ScreenEA(),0),GetOpType(ScreenEA(),1));
//Warning("Address: %x",PrevHead(0x00506ddd,0x00505000)); // search previous

//Warning("Address: %x",NextHead(0x00506ddd,0x00505000)); // search previous

//Warning("Address: %d",ItemSize(0x00506ddd));

//Warning("Address: %d",GetOpType(0x00506dd5,1));
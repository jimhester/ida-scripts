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
    else{
        if(secondOpType == 2 || strstr(secondOpStr,"offset") != -1){
            hasMemoryLoc = 2;
        }
    }
    if(hasMemoryLoc == 1){
        startItr = 5;
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
    return(searchString);
}

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

static getSmallestSearchString(start)
{
    auto forward,reverse,revString,search,itr,value;
    itr = 0;
    forward = NextHead(start,start+100);
    reverse = PrevHead(start,start-100);
    search = getSearchString(start);
    value = strlen(search)-7;
    while(getOccurances(search) == BADADDR && itr < 20){
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
        itr = itr + 1;
    }
    return(form("%s\;%d",search,countSpaces(substr(search,0,value))));
}
static pattern_generator(start,filename,showFile){
    auto checkStart,searchString,arrayId,currXRef,arrayIndex,stringLength,hFile,itr,shiftAmount,xrefCutoff;
    xrefCutoff = 100; // make this higher if you want more xrefs
    shiftAmount = 0;
    hFile = fopen(filename, "wb");
    currXRef = DfirstB(start);
    if(currXRef == -1){
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
        pattern_generator(start,szFilePath,1);
    }
    else{
        auto directory,openFilename,line,fileHandle,outHandle;
        directory = AskStr("C:\\", "Please enter a location to dump the files");
        openFilename = AskFile(0,"*.*", "File with addresses to generate patterns for");
        outHandle = fopen(directory + "\\filenames.txt","w");
        fileHandle = fopen(openFilename, "r");
        line = readstr(fileHandle);
        while(line != -1 ){
            auto addressName, address,spaceLoc;
            spaceLoc = strstr(line," ");
            addressName = substr(line,0,spaceLoc);
            address = xtol(substr(line,spaceLoc+1,strlen(line)));
            Message("Finding Patterns for for %s, at %x\n",addressName, address);
            fprintf(outHandle, "%s\n", directory + "\\" + addressName + "_patterns.txt");
            pattern_generator(address, directory + "\\" + addressName + "_patterns.txt",0);
            line=readstr(fileHandle);
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
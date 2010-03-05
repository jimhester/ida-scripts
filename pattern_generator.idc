#include <idc.idc>

static getSearchString(start)
{
    auto end;
    auto i;
    auto hasMemoryLoc;
    auto searchString;
    
    hasMemoryLoc = 0;
    end = ItemSize(start);
    
    if(GetOpType(start,0) == 2 || GetOpType(start,1) == 2){
        hasMemoryLoc = 1;
    }
    if(hasMemoryLoc){
        end = end - 4;
    }
    searchString = form("%02x",Byte(start));
    for(i = 1;i < end;i++){
        searchString = searchString + " " + form("%02x",Byte(start+i));
    }
    if(hasMemoryLoc){
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
    auto forward,reverse,search,itr;
    itr = 0;
    forward = NextHead(start,start+100);
    reverse = PrevHead(start,start-100);
    search = getSearchString(start);
    while(getOccurances(search) == BADADDR && itr < 20){
        if(itr % 2 == 0){
            search = getSearchString(reverse) + " " + search;
            reverse = PrevHead(reverse, reverse-100);
        }
        else{
            search = search + " " + getSearchString(forward);
            forward = NextHead(forward, forward + 100);
        }
        itr = itr + 1;
    }
    return(search);
}
static main(void){
    auto start,searchString,arrayId,currXRef,arrayIndex,stringLength,szFilePath,hFile,itr;
    szFilePath = AskFile(1, "*.txt", "Select output dump file:");
    hFile = fopen(szFilePath, "wb");
    start = ScreenEA();
    currXRef = DfirstB(start);
    searchString = getSmallestSearchString(currXRef);
    fprintf(hFile,"%s\r\n", searchString);
    currXRef = DnextB(start,currXRef);
    Message("%d",1);
    itr = 2;
    while(currXRef != -1){
        Message(",%d", itr);
        searchString = getSmallestSearchString(currXRef);
        fprintf(hFile,"%s\r\n", searchString);
        currXRef = DnextB(start,currXRef);
        itr=itr+1;
    }
    fclose(hFile);
    Exec("start notepad " + szFilePath);
}

    //for(i = ScreenEA();
    //Warning("%d %d",GetOpType(ScreenEA(),0),GetOpType(ScreenEA(),1));
//Warning("Address: %x",PrevHead(0x00506ddd,0x00505000)); // search previous

//Warning("Address: %x",NextHead(0x00506ddd,0x00505000)); // search previous

//Warning("Address: %d",ItemSize(0x00506ddd));

//Warning("Address: %d",GetOpType(0x00506dd5,1));
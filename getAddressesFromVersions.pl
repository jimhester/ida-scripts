#!/usr/bin/perl

#run this in the ida home directory, not the idc directory

#first argument should be a file with the paths to the DF versions you want to get addresses for
#second argument should be a file with the patterns you want to use
#third argument should be the name of the address

my ($DFPathsFile,$patternsFile, $addressName) = @ARGV;

open PATHS, $DFPathsFile or die $!;

open OUT, ">outAddress";
print OUT "$addressName\n";
close OUT;

system("copy $patternsFile addressFile.txt");

while(<PATHS>){
    my($id, $path) = split;
    open OUT, ">>outAddress";
    print OUT "$id ";
    close OUT;
    system("idag.exe -A -SgetAddressFromDatabase.idc $path");
    if($? == -1){
        print STDERR "Address not found in $id\n";
        last;
    }
    print STDERR "Address found for $id\n";
}

system("copy outAddress $addressName.txt");
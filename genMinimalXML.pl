#!/usr/bin/perl

use warnings;
use strict;

my (%file1,%file2) = () x 2;
my ($MD51, $MD52, $pe_timestamp1, $pe_timestamp2) = (0) x 4;

my ($file1, $file2) = @ARGV;
open FILE1, $file1 or die $!;
while(<FILE1>){
    my($name, $address) = split;
    if($name eq "md5"){
        $MD51 = $address;
    }
    elsif($name eq "pe_timestamp"){
        $pe_timestamp1 = hex($address);
    }
    else{
        $file1{$name} = hex($address);
    }
}
open FILE2, $file2 or die $!;
while(<FILE2>){
    my($name, $address) = split;
    if($name eq "md5"){
        $MD52 = $address;
    }
    elsif($name eq "pe_timestamp"){
        $pe_timestamp2 = hex($address);
    }
    else{
        $file2{$name} = hex($address);
    }
}

my %rebaseCounts = ();
for my $address (keys %file2){
    if(exists $file1{$address}){
        $rebaseCounts{$file2{$address}-$file1{$address}}++;
    }
}

my $rebaseAmount = (sort {$b <=> $a} keys %rebaseCounts)[0];
my $rebased = undef;
if($rebaseCounts{$rebaseAmount} > 10){
    printf("rebase=\"0x%x\">\n", $rebaseAmount);
    $rebased=1;
}

printf("<HexValue name=\"pe_timestamp\">0x%08x</HexValue>\n",$pe_timestamp2);
print "<String name=\"md5\">$MD52</String>\n";
for my $address(keys %file2){
    if(not $rebased or ($rebased and $file2{$address}-$file1{$address} != $rebaseAmount)){
        printf("<Address name=\"$address\">0x%08x</Address>\n",$file2{$address});
    }
}
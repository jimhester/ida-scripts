#!/usr/bin/perl

use warnings;
use strict;

use Data::Dumper;
use XML::Twig;

my %updates = ();
my $xmlFile = pop;
my $updateElement;
for my $updateFile(@ARGV){
  open UPDATES, $updateFile or die $!;

  $updateElement = <UPDATES>;
  chomp $updateElement;
  while(<UPDATES>){
    my($version, $address) = split;
    $updates{$updateElement}{$version} = hex($address);
  }
}
my $twig= new XML::Twig(twig_handlers => { Entry => \&entry },keep_atts_order=>1 );
$twig->set_pretty_print( 'record');

$twig->parsefile( $xmlFile);
$twig->print;

sub entry{
  my ($twig,$field) = @_;
  if($field->atts->{'id'} =~ /meta/){ #ignore meta entries
    return;
  }
  for my $element(keys %updates){
    $updateElement=$element;
    my $currentAddress = getCurrentAddress($field);
    if($currentAddress){
          printf(STDERR "$updateElement %s 0x%x\n", $field->atts->{'id'}, $currentAddress);
    }
    if(not exists $updates{$updateElement}{$field->atts->{'id'}}){
      return;
    }
    if(not $currentAddress or $currentAddress != $updates{$updateElement}{$field->atts->{'id'}}){
      my $currentAddressElm = $field->first_child(\&correctAddress);
      if(defined $currentAddressElm){
	printf(STDERR "Changing $updateElement %s to 0x%x\n", $field->atts->{'id'},$updates{$updateElement}{$field->atts->{'id'}});
	$currentAddressElm->set_text(sprintf("0x%x",$updates{$updateElement}{$field->atts->{'id'}}));
      }
      else{
	my $added;
	my $elt= XML::Twig::Elt->new(Address => { name => $updateElement },sprintf("0x%x",$updates{$updateElement}{$field->atts->{'id'}}));
	for my $child($field->children){
	  if($child->atts->{'name'} !~ /pe_timestamp|md5/ and ($child->atts->{'name'} cmp $updateElement) >0){
	    printf(STDERR "Adding $updateElement 0x%x to %s\n", $updates{$updateElement}{$field->atts->{'id'}},$field->atts->{'id'});
	    $elt->paste('before', $child);
	    $added = 1;
	    last;
	  }
	}
	if(not $added){
	  printf(STDERR "Adding $updateElement 0x%x to %s\n", $updates{$updateElement}{$field->atts->{'id'}},$field->atts->{'id'});
	  $elt->paste('last_child', $field);
	}
      }
    }
  }
}

sub getCurrentAddress{
  my ($field) = @_;
  my $rebase = 0;
  my $address;
  if(exists $field->atts->{'rebase'}){
    $rebase += getRebase($field->atts->{'rebase'});
  }
  my $prevField = $field;
  while(not defined $address){
    my $addressElm = $prevField->first_child(\&correctAddress);
    if($addressElm){
      return $rebase+getRebase($addressElm->text);
    }
    my $base = $prevField->prev_sibling();
    while(defined $base and defined $base->atts and $base->atts->{'id'} ne $prevField->atts->{'base'}){
      $base = $base->prev_sibling();
    }
    if(not defined $base or not defined $base->atts){
      return undef;
    }
    if(exists $base->atts->{'rebase'}){
      $rebase += getRebase($base->atts->{'rebase'});
    }
    $prevField = $base;
  }
}
sub correctAddress{
  my($checkElm) = @_;
  if(exists $checkElm->atts->{'name'} and $checkElm->atts->{'name'} eq $updateElement){
    return 1;
  }
  return 0;
}

sub getRebase{
  my($value) = shift;
  if($value =~ /^-/){
    return(-1*hex(substr($value,1)));
  }
  return(hex($value));
}

#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab

use strict;
use warnings;
use Data::Dumper;
use AnyEvent;
use File::Temp qw(tempfile);
use v5.10;

sub generate_pubkey_for {
    my ($private_key) = @_;

    my ($fh, $name) = tempfile();
    print $fh $private_key;
    chomp(my $pubkey = qx(seccure-key -F $name -q 2>/dev/null));
    close($fh);
    return $pubkey;
}

say "Enter password:";
chomp(my $pw = <STDIN>);
say "pw = $pw";
my $pubkey = generate_pubkey_for($pw);
say "pubkey = $pubkey";

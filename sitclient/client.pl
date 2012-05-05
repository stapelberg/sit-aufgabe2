#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab

use strict;
use warnings;
use Data::Dumper;
use AnyEvent;
use AnyEvent::HTTP;
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

sub get_from_server {
    my ($path, $headers) = @_;
    my $cv = AE::cv;
    my $timeout;
# TODO: don’t hardcode the first part of the URL
    http_get "http://localhost:3000$path",
        headers => $headers,
        sub {
            $cv->send($_[0], $_[1]);
            undef $timeout;
        };
    $timeout = AnyEvent->timer(after => 1, cb => sub { $cv->send; undef $timeout; });
    return $cv->recv;
}

say "Enter username:";
chomp(my $username = <STDIN>);
say "Enter password:";
chomp(my $pw = <STDIN>);
say "pw = $pw";
my $pubkey = generate_pubkey_for($pw);
say "pubkey = $pubkey";

# 2: signierten pubkey des servers abrufen
my $signed_server_pubkey = get_from_server("/signed_server_pubkey/$username");
die "Could not get pubkey (timeout)" unless defined($signed_server_pubkey);
say 'pubkey = ' . Dumper($signed_server_pubkey);

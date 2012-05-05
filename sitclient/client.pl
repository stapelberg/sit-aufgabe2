#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab

use strict;
use warnings;
use Data::Dumper;
use AnyEvent;
use AnyEvent::HTTP;
use File::Temp qw(tempfile);
# not in core
use JSON::XS;
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
$signed_server_pubkey = decode_json($signed_server_pubkey);

say 'pubkey = ' . Dumper($signed_server_pubkey);

# 3: Verify the signature.
my ($sigfh, $signame) = tempfile();
my ($pubkeyfh, $pubkeyname) = tempfile();
print $sigfh $signed_server_pubkey->{signature};
print $pubkeyfh $signed_server_pubkey->{pubkey};
system(('seccure-verify', '-i', $pubkeyname, '-s', $signame, $pubkey));
if ($? == -1) {
    die "failed to execute seccure-verify: $!\n";
} elsif ($? & 127) {
    die "seccure-verify died with signal " . ($? & 127);
} else {
    if (($? >> 8) != 0) {
        die "pubkey verification failed.";
    }
}
close($sigfh);
close($pubkeyfh);

say "Successfully verified server signature.";

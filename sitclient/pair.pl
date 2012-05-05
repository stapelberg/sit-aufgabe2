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

sub post_to_server {
    my ($path, $body, $headers) = @_;
    my $cv = AE::cv;
    my $timeout;
# TODO: don’t hardcode the first part of the URL
    http_post "http://localhost:3000$path",
        $body,
        headers => $headers,
        recurse => 0,
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

# 1: nutzer registrieren
my $new_user_json = encode_json({
    name => $username,
    publickey => $pubkey,
    expiration => '2012-05-05',
});
my $result = post_to_server('/register_new_user', $new_user_json);
say "registered, result = " . $result;

# 2: pubkey des servers abrufen und signieren
my $server_pubkey = get_from_server('/server_pubkey');
die "Could not get server pubkey" unless defined($server_pubkey);

my ($fh, $name) = tempfile();
my ($pwfh, $pwname) = tempfile();
my ($sigfh, $signame) = tempfile();
print $fh $server_pubkey;
print $pwfh $pw;
say "tempfile with server pubkey = $name, pwfile = $pwname";
system(qq|seccure-sign -i $name -F $pwname -s $signame 2>/dev/null|);
chomp(my $signature = <$sigfh>);
close($fh);
close($pwfh);

say "signature = $signature";

my $sig_json = encode_json({
    name => $username,
    signature => $signature,
});
$result = post_to_server('/store_signature', $sig_json);
say "stored signature, result = " . $result;

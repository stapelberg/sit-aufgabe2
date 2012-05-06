#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab

use strict;
use warnings;
use Data::Dumper;
use AnyEvent;
use AnyEvent::HTTP;
use File::Temp qw(tempfile);
use MIME::Base64;
# not in core
use JSON::XS;
use IO::All;
use Crypt::Rijndael;
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
my $pubkey = generate_pubkey_for($pw);

# 2: signierten pubkey des servers abrufen
my $signed_server_pubkey = get_from_server("/signed_server_pubkey/$username");
die "Could not get pubkey (timeout)" unless defined($signed_server_pubkey);
$signed_server_pubkey = decode_json($signed_server_pubkey);

# 3: Verify the signature.
my ($sigfh, $signame) = tempfile();
my ($pubkeyfh, $pubkeyname) = tempfile();
print $sigfh $signed_server_pubkey->{signature};
print $pubkeyfh $signed_server_pubkey->{pubkey};
open my $oldout, ">&STDOUT";  # "dup" the stdout filehandle
open my $olderr, ">&STDOUT";  # "dup" the stdout filehandle
close STDOUT;
close STDERR;
system(('seccure-verify', '-i', $pubkeyname, '-s', $signame, $pubkey));
open STDOUT, '>&', $oldout;  # restore the dup'ed filehandle to STDOUT
open STDERR, '>&', $olderr;  # restore the dup'ed filehandle to STDERR
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

# 4: Request the session key from the server.
my $session_key = get_from_server("/session_key/$username");
$session_key = decode_base64($session_key);
my ($skfh, $skname) = tempfile();
my ($decryptedfh, $decryptedname) = tempfile();
my ($pwfh, $pwname) = tempfile();
say $pwfh $pw;
binmode $skfh;
print $skfh $session_key;
open $oldout, ">&STDOUT";  # "dup" the stdout filehandle
open $olderr, ">&STDOUT";  # "dup" the stdout filehandle
close STDOUT;
close STDERR;
open STDOUT, '>', '/dev/null';
open STDERR, '>', '/dev/null';
system(('seccure-veridec', '-i', $skname, '-o', $decryptedname, '-F', $pwname, $signed_server_pubkey->{pubkey}));
close STDOUT;
close STDERR;
open STDOUT, '>&', $oldout;  # restore the dup'ed filehandle to STDOUT
open STDERR, '>&', $olderr;  # restore the dup'ed filehandle to STDERR
if ($? == -1) {
    die "failed to execute seccure-veridec: $!\n";
} elsif ($? & 127) {
    die "seccure-veridec died with signal " . ($? & 127);
} else {
    if (($? >> 8) != 0) {
        die "session key decryption failed.";
    }
}
close($skfh);
$session_key = io($decryptedname)->binary->slurp;
close($decryptedfh);
close($pwfh);

# 5: Encrypt the file with the session key and send it to the server.

my $key = substr($session_key, 0, 32);
my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());

$cipher->set_iv(substr($session_key, 32, 16));
my $payload = 'trolol, es funktioniert';
while ((length($payload) % 16) != 0) {
    $payload .= "X";
}
my $crypted = $cipher->encrypt($payload);

say "Storing data on server…";
my $result = post_to_server("/store_encrypted/$username", encode_base64($crypted));
say "Server says: $result";

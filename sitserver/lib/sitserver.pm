# vim:ts=4:sw=4:expandtab
package sitserver;
use Dancer ':syntax';
use Dancer::Plugin::Database;
# in core
use MIME::Base64;
use File::Temp qw(tempfile);
use Data::Dumper;
use IO::All; # not in core

our $VERSION = '0.1';

my $pubkey = undef;

sub get_server_pubkey() {
    # Generate the publickey from the private key if necessary.
    if (!defined($pubkey)) {
        my ($fh, $name) = tempfile();
        print $fh setting('server_privkey');
        $pubkey = qx(seccure-key -F $name -q 2>/dev/null);
        chomp($pubkey);
        close($fh);
    }
    return $pubkey;
}

get '/' => sub {
    return 'This webserver is accessible via SIT only';
};

get '/server_pubkey' => sub {
    return get_server_pubkey();
};

get '/signed_server_pubkey/:username' => sub {
    my @sigs = database->quick_select('signatures', { name => param('username') });
    if (@sigs != 1) {
        return 'ERROR: Signature not found';
    }
    return to_json { pubkey => get_server_pubkey(), signature => $sigs[0]->{signature} };
};

get '/session_key/:username' => sub {
    open(my $randfh, '<', '/dev/urandom');
    binmode $randfh;
    my $random_numbers;
    read($randfh, $random_numbers, 1024);
    close($randfh);

    # TODO: save the hash of that and repeat until we have unique random numbers

    my @pubkeys = database->quick_select('users', { name => param('username') });
    my $pubkey = $pubkeys[0]->{publickey};

    my ($rndfh, $rndname) = tempfile();
    my ($outfh, $outname) = tempfile();
    my ($pwfh, $pwname) = tempfile();
    print $rndfh $random_numbers;
    say $pwfh setting('server_privkey');
    system(qq|seccure-signcrypt -i $rndname -o $outname -F $pwname '$pubkey'|);
    debug "outname = $outname";
    return encode_base64(io($outname)->binary->slurp);
};

post '/register_new_user' => sub {
    my $params = from_json(request->body);
    my $username = $params->{'name'} // '';
    my $pubkey = $params->{'publickey'} // '';
    my $expiration = $params->{'expiration'} // '';

    if ($username eq '' ||
        $pubkey eq '' ||
        $expiration eq '') {
        return 'ERROR: Parameter missing (need name, publickey, expiration)';
    }

    debug "Registering new user $username with pubkey $pubkey and expiration $expiration";
    database->quick_insert('users', {
        name => $username,
        publickey => $pubkey,
        expiration => $expiration,
    });
    return "yay";
};

post '/store_signature' => sub {
    my $params = from_json(request->body);
    my $username = $params->{'name'} // '';
    my $signature = $params->{'signature'} // '';

    if ($username eq '' ||
        $signature eq '') {
        return 'ERROR: Parameter missing (need name, signature)';
    }

    debug "Storing signature $signature for username $username";
    database->quick_insert('signatures', {
        name => $username,
        signature => $signature,
    });
    return "yay";
};

true;

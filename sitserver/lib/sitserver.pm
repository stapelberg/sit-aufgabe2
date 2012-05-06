# vim:ts=4:sw=4:expandtab
package sitserver;
use Dancer ':syntax';
use Dancer::Plugin::Database;
# in core
use MIME::Base64;
use File::Temp qw(tempfile);
use Data::Dumper;
use IO::All; # not in core
use Digest::SHA qw(sha1_hex);
use POSIX qw(strftime);
use Crypt::Rijndael;

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
    my $db = database;
    my $random_numbers;
    while (1) {
        open(my $randfh, '<', '/dev/urandom');
        binmode $randfh;
        read($randfh, $random_numbers, 1024);
        close($randfh);

        my $hash = sha1_hex($random_numbers);
        my @old_session_keys = $db->quick_select('session_keys', { session_key_hash => $hash });
        if (@old_session_keys == 0) {
            $db->quick_insert('session_keys', {
                session_key => encode_base64($random_numbers),
                session_key_hash => $hash,
                created => strftime("%Y-%m-%d %H:%M:%S", localtime()),
                name => param('username'),
            });
            last;
        }
    }

    my @pubkeys = database->quick_select('users', { name => param('username') });
    my $pubkey = $pubkeys[0]->{publickey};

    my ($rndfh, $rndname) = tempfile();
    my ($outfh, $outname) = tempfile();
    my ($pwfh, $pwname) = tempfile();
    print $rndfh $random_numbers;
    say $pwfh setting('server_privkey');
    system(qq|seccure-signcrypt -i $rndname -o $outname -F $pwname '$pubkey'|);
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

post '/store_encrypted/:username' => sub {
    my $payload = decode_base64(request->body);

    # Get the latest session key and try to decrypt this message.
    my @session_keys = @{database->selectall_arrayref(q|SELECT * FROM session_keys WHERE name = ? ORDER BY created DESC LIMIT 1|, { Slice => {} }, param('username'))};
    if (@session_keys < 1) {
        return "No session key found.";
    }

    my $session_key = decode_base64($session_keys[0]->{session_key});
    my $hash = sha1_hex($session_key);
    if ($hash ne $session_keys[0]->{session_key_hash}) {
        debug "Hash does not match";
        status 500;
        return "BUG: hash does not match";
    }
    my $key = substr($session_key, 0, 32);
    my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());

    $cipher->set_iv(substr($session_key, 32, 16));
    my $decrypted = $cipher->decrypt($payload);
    debug 'decrypted = ' . Dumper($decrypted);
    return "OK";
};

true;

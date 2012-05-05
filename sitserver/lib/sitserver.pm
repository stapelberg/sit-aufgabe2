# vim:ts=4:sw=4:expandtab
package sitserver;
use Dancer ':syntax';
use Dancer::Plugin::Database;
# in core
use MIME::Base64;
use File::Temp qw(tempfile);

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

post '/register_new_user' => sub {
    my $username = param('name') // '';
    my $pubkey = param('publickey') // '';
    my $expiration = param('expiration') // '';

    if ($username eq '' ||
        $pubkey eq '' ||
        $expiration eq '') {
        return 'ERROR: Parameter missing (need name, publickey, expiration)';
    }

    debug "Registering new user $username with pubkey $pubkey and expiration $expiration";
    my $db = database;
    $db->quick_insert('users', {
        name => $username,
        publickey => $pubkey,
        expiration => $expiration,
    });
    return "yay";
};

true;

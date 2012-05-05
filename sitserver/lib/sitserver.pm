# vim:ts=4:sw=4:expandtab
package sitserver;
use Dancer ':syntax';
use Dancer::Plugin::Database;

our $VERSION = '0.1';


get '/' => sub {
    return 'This webserver is accessible via SIT only';
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

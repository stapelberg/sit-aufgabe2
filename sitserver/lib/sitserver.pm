package sitserver;
use Dancer ':syntax';

our $VERSION = '0.1';

get '/' => sub {
    return 'This webserver is accessible via SIT only';
};

true;

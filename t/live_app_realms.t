use strict;
use warnings;

use Test::More tests => 1;

use lib 't/lib';
use Catalyst::Test qw/AuthRealmTestApp/;

ok(get("/moose"), "get ok");

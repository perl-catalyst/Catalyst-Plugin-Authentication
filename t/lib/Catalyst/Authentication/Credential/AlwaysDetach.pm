package Catalyst::Authentication::Credential::AlwaysDetach;
use strict;
use warnings;

sub new {
    bless {}, __PACKAGE__;
}

sub authenticate {
    my ( $self, $c, $realm, $auth_info ) = @_;
    $c->detach;
}

no Moose;
1;


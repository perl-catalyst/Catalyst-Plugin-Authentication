package Catalyst::Plugin::Authentication::Store::Null;

use strict;
use warnings;

use Catalyst::Plugin::Authentication::User::Hash;

use base qw( Class::Accessor::Fast );

BEGIN {
    __PACKAGE__->mk_accessors( qw( _config ) );
}

sub new {
    my ( $class, $config, $app) = @_;
    bless { _config => $config }, $class;
}

sub for_session {
	my ( $self, $c, $user ) = @_;
    return $user;
}

sub from_session {
	my ( $self, $c, $user ) = @_;
    return $user;
}

sub find_user {
    my ( $self, $userinfo, $c ) = @_;
    return bless $userinfo, 'Catalyst::Plugin::Authentication::User::Hash';
}

sub user_supports {
    my $self = shift;
    Catalyst::Plugin::Authentication::User::Hash->supports(@_);
}

1;

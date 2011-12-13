package AuthRealmTestAppProgressive::Controller::Root;
use warnings;
use strict;
use base qw/Catalyst::Controller/;

__PACKAGE__->config( namespace => '' );

use Test::More;
use Test::Exception;

sub progressive : Local {
    my ( $self, $c ) = @_;

    foreach my $realm ( keys %AuthRealmTestAppProgressive::members ) {
        while ( my ( $user, $info ) =
            each %{ $AuthRealmTestAppProgressive::members{$realm} } )
        {
            my $res;
            my $ok = eval {
                $res = $c->authenticate(
                    { username => $user, password => $info->{password} },
                );
                1;
            };
            ok( !$@,                       "authentication passed." );
            ok( $ok,                       "user authenticated" );
            ok( $c->user_in_realm($realm), "user in proper realm" );
        }
    }
    $c->res->body("ok");
}

1;


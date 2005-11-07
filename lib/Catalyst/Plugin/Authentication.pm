#!/usr/bin/perl

package Catalyst::Plugin::Authentication;

use base qw/Class::Accessor::Fast Class::Data::Inheritable/;

BEGIN {
    __PACKAGE__->mk_accessors(qw/user/);
    __PACKAGE__->mk_classdata(qw/default_auth_store/);
}

use strict;
use warnings;

our $VERSION = "0.01";

sub set_authenticated {
    my ( $c, $user ) = @_;

    $c->user($user);

    if (    $c->isa("Catalyst::Plugin::Session")
        and $c->config->{authentication}{use_session} )
    {
        $c->session->{__user} = $user->for_session
          if $user->supports("session");
        $c->session->{__user_class} = ref $user;
    }
}

sub logout {
    my $c = shift;

    $c->user(undef);

    if (    $c->isa("Catalyst::Plugin::Session")
        and $c->config->{authentication}{use_session} )
    {
        delete @{ $c->session }{qw/__user __user_class/};
    }
}

sub get_user {
    my ( $c, $uid ) = @_;

    if ( my $store = $c->default_auth_store ) {
        return $store->get_user($uid);
    }
    else {
        Catalyst::Exception->throw(
                "The user id $uid was passed to an authentication "
              . "plugin, but no default store was specified" );
    }
}

sub prepare {
    my $c = shift->NEXT::prepare(@_);

    if (    $c->isa("Catalyst::Plugin::Session")
        and $c->default_auth_store
        and !$c->user )
    {
        if ( $c->sessionid and my $user = $c->session->{__user} ) {
            $c->user( $c->session->{__user_class}->from_session( $c, $user ) );
            $c->request->user( $c->user );
        }
    }

    return $c;
}

sub setup {
    my $c = shift;

    my $cfg = $c->config->{authentication};

    %$cfg = (
        use_session => 1,
        %$cfg,
    );

    $c->NEXT::setup(@_);
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication - 

=head1 SYNOPSIS

	use Catalyst qw/
		Authentication
		Authentication::Store::Foo
		Authentication::Credential::Password
	/;

=head1 DESCRIPTION

The authentication plugin is used by the various authentication and
authorization plugins in catalyst.

It defines the notion of a logged in user, and provides integration with the 

=head1 METHODS

=over 4 

=item logout

Delete the currently logged in user from C<user> and the session.

=item user

Returns the currently logged user or undef if there is none.

=item get_user $uid

Delegate C<get_user> to the default store.

=item default_auth_store

Returns C<< $c->config->{authentication}{store} >>.

=back

=head1 INTERNAL METHODS

=over 4

=item set_authenticated $user

Marks a user as authenticated. Should be called from a
C<Catalyst::Plugin::Authentication::Credential> plugin after successful
authentication.

This involves setting C<user> and the internal data in C<session> if
L<Catalyst::Plugin::Session> is loaded.

=item prepare

Revives a user from the session object if there is one.

=item setup

Sets the default configuration parameters.

=item 

=back

=head1 CONFIGURATION

=over 4

=item use_session

Whether or not to store the user's logged in state in the session, if the
application is also using the L<Catalyst::Plugin::Authentication> plugin.

=back

=cut



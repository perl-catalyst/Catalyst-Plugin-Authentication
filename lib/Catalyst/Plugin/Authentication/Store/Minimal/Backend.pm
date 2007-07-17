#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Store::Minimal::Backend;

use strict;
use warnings;

use Catalyst::Plugin::Authentication::User::Hash;
use Scalar::Util ();

sub new {
    my ( $class, $config, $app) = @_;

    bless { hash => $config->{'users'} }, $class;
}

sub from_session {
	my ( $self, $c, $id ) = @_;

	return $id if ref $id;

	$self->find_user( { id => $id } );
}

## this is not necessarily a good example of what find_user can do, since all we do is   
## look up with the id anyway.  find_user can be used to locate a user based on other 
## combinations of data.  See C::P::Authentication::Store::DBIx::Class for a better example
sub find_user {
    my ( $self, $userinfo, $c ) = @_;

    my $id = $userinfo->{'id'};
    
    return unless exists $self->{'hash'}{$id};

    my $user = $self->{'hash'}{$id};

    if ( ref $user ) {
        if ( Scalar::Util::blessed($user) ) {
			$user->id( $id );
            return $user;
        }
        elsif ( ref $user eq "HASH" ) {
            $user->{id} ||= $id;
            return bless $user, "Catalyst::Plugin::Authentication::User::Hash";
        }
        else {
            Catalyst::Exception->throw( "The user '$id' is a reference of type "
                  . ref($user)
                  . " but should be a HASH" );
        }
    }
    else {
        Catalyst::Exception->throw(
            "The user '$id' is has to be a hash reference or an object");
    }

    return $user;
}

sub user_supports {
    my $self = shift;

    # choose a random user
    scalar keys %{ $self->{hash} };
    ( undef, my $user ) = each %{ $self->{hash} };

    $user->supports(@_);
}

## Backwards compatibility
#
# This is a backwards compatible routine.  get_user is specifically for loading a user by it's unique id
# find_user is capable of doing the same by simply passing { id => $id }  
# no new code should be written using get_user as it is deprecated.
sub get_user {
    my ( $self, $id ) = @_;
    $self->find_user({id => $id});
}



__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Store::Minimal::Backend - Minimal
authentication storage backend.

=head1 SYNOPSIS

    # you probably just want Store::Minimal under most cases,
    # but if you insist you can instantiate your own store:

    use Catalyst::Plugin::Authentication::Store::Minimal::Backend;

    use Catalyst qw/
        Authentication
        Authentication::Credential::Password
    /;

    my %users = (
        user => { password => "s3cr3t" },
    );
    
    our $users = Catalyst::Plugin::Authentication::Store::Minimal::Backend->new(\%users);

    sub action : Local {
        my ( $self, $c ) = @_;

        $c->login( $users->get_user( $c->req->param("login") ),
            $c->req->param("password") );
    }

=head1 DESCRIPTION

You probably want L<Catalyst::Plugin::Authentication::Store::Minimal>, unless
you are mixing several stores in a single app and one of them is Minimal.

Otherwise, this lets you create a store manually.

=head1 METHODS

=over 4

=item new $hash_ref

Constructs a new store object, which uses the supplied hash ref as it's backing
structure.

=item get_user $id

Keys the hash by $id and returns the value.

If the return value is unblessed it will be blessed as
L<Catalyst::Plugin::Authentication::User::Hash>.

=item from_session $id

Delegates to C<get_user>.

=item user_supports

Chooses a random user from the hash and delegates to it.

=back

=cut



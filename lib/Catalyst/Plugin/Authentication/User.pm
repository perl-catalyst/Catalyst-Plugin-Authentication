#!/usr/bin/perl

package Catalyst::Plugin::Authentication::User;

use strict;
use warnings;


## chances are you want to override this.
sub id { shift->get('id'); }

## returns the realm the user came from - not a good idea to override this.
sub auth_realm {
    my $self = shift;
    $self->{'realm'};
}



sub supports {
    my ( $self, @spec ) = @_;

    my $cursor = $self->supported_features;

    # traverse the feature list,
    for (@spec) {
        #die "bad feature spec: @spec" if ref($cursor) ne "HASH";
        return if ref($cursor) ne "HASH";

        $cursor = $cursor->{$_};
    }

    return $cursor;
}

## REQUIRED.
## get should return the value of the field specified as it's single argument from the underlying
## user object.  This is here to provide a simple, standard way of accessing individual elements of a user
## object - ensuring no overlap between C::P::A::User methods and actual fieldnames.
## this is not the most effecient method, since it uses introspection.  If you have an underlying object
## you most likely want to write this yourself.
sub get {
    my ($self, $field) = @_;
    
    my $object;
    if ($object = $self->get_object && $object->can($field)) {
        return $object->$field();
    } else {
        return undef;
    }
}

## REQUIRED.
## get_object should return the underlying user object.  This is for when more advanced uses of the 
## user is required.  Modifications to the existing user, etc.  Changes in the object returned
## by this routine may not be reflected in the C::P::A::User object - if this is required, re-authenticating
## the user is probably the best route to take.
## note that it is perfectly acceptable to return $self in cases where there is no underlying object.
sub get_object {
    return shift;
}

## this is an internal routine.  I suggest you don't rely on it's presence. 
## sets the realm the user came from.
sub _set_auth_realm {
    my ($self, $realmname) = @_;
    $self->{'realm'} = $realmname;
}

## Backwards Compatibility
## you probably want auth_realm, in fact.  but this does work for backwards compatibility.
sub store { 
    my ($self) = @_;
    return $self->auth_realm->{store};
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::User - Base class for user objects.

=head1 SYNOPSIS

	package MyStore::User;
	use base qw/Catalyst::Plugin::Authentication::User/;

=head1 DESCRIPTION

This is the base class for authenticated 

=head1 METHODS

=over 4

=item id

A unique ID by which a user can be retrieved from the store.

=item store

Should return a class name that can be used to refetch the user using it's
ID.

=item supports

An introspection method used to determine what features a user object has, to support credential and authorization plugins.

=item 

=back

=cut



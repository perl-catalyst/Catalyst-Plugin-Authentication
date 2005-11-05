#!/usr/bin/perl

package Catalyst::Plugin::Authentication::User::Hash;
use base qw/Catalyst::Plugin::Authentication::User/;

use strict;
use warnings;

sub new {
	my $class = shift;

	bless { @_ }, $class;
}

sub AUTOLOAD {
    my $self = shift;
    ( my $key ) = ( our $AUTOLOAD =~ m/([^:]*)$/ );

    $self->{$key} = shift if @_;
    $self->{$key};
}

my %features = (
    password => {
        clear   => ["password"],
        crypted => ["crypted_password"],
        hashed  => [qw/hashed_password hash_algorithm/],
    },
    session => 1,
);

sub supports {
    my ( $self, @spec ) = @_;

    my $cursor = \%features;

    # traverse the feature list,
    for (@spec) {
        die "bad feature spec: @spec"
          if ref($cursor) ne "HASH"
          or !ref( $cursor = $cursor->{$_} );
    }

    die "bad feature spec: @spec" unless ref $cursor eq "ARRAY";

    # check that all the keys required for a feature are in here
    foreach my $key (@$cursor) {
        return undef unless exists $self->{$key};
    }

    return 1;
}

sub for_session {
    my $self = shift;

    return $self;    # let's hope we're serialization happy
}

sub from_session {
    my ( $self, $c, $user ) = @_;

    return $user;    # if we're serialization happy this should work
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::User::Hash - An easy authentication user
object based on hashes.

=head1 SYNOPSIS

	use Catalyst::Plugin::Authentication::User::Hash;
	
	Catalyst::Plugin::Authentication::User::Hash->new(
		password => "s3cr3t",
	);

=head1 DESCRIPTION

This implementation of authentication user handles is supposed to go hand in
hand with L<Catalyst::Plugin::Authentication::Store::Minimal>.

=head1 METHODS

=over 4

=item new @pairs

Create a new object with the key-value-pairs listed in the arg list.

=item supports

Checks for existence of keys that correspond with features.

=item for_session

Just returns $self, expecting it to be serializable.

=item from_session

Just passes returns the unserialized object, hoping it's intact.

=item AUTOLOAD

Accessor for the key whose name is the method.

=back

=head1 SEE ALSO

L<Hash::AsObject>

=cut


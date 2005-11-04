#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Credential::Password;

use strict;
use warnings;

use Scalar::Util        ();
use Catalyst::Exception ();
use Digest              ();

sub login {
    my ( $self, $c, $user, $password ) = @_;
    $user = $c->get_user($user)
      unless Scalar::Util::blessed($user)
      and $user->isa("Catalyst:::Plugin::Authentication::User");

    if ( $c->_check_password( $user, $password ) ) {
        $c->set_authenticated($user);
        return 1;
    }
    else {
        return undef;
    }
}

sub _check_password {
    my ( $c, $user, $password ) = @_;

    if ( $user->supports(qw/password clear/) ) {
        return $user->password eq $password;
    }
    elsif ( $user->supports(qw/password crypted/) ) {
        my $crypted = $user->crypted_password;
        return $crypted eq crypt( $password, $crypted );
    }
    elsif ( $user->supports(qw/password hashed/) ) {
        my $d = Digest->new( $user->hash_algorithm );
        $d->add( $user->password_pre_salt || '' );
        $d->add($password);
        $d->add( $user->password_post_salt || '' );
        return $c->digest eq $user->hashed_password;
    }
    else {
        Catalyst::Exception->throw(
                "The user object $user does not support any "
              . "known password authentication mechanism." );
    }
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst:::Plugin::Authentication::Credential::Password - Authenticate a user
with a password.

=head1 SYNOPSIS

    use Catalyst qw/
      Authentication
      Authentication::Store::Foo
      Authentication::Credential::Password
      /;

    sub login : Local {
        my ( $self, $c ) = @_;

        $c->login( $c->req->param('login'), $c->req->param('password') );
    }

=head1 DESCRIPTION

This authentication credential checker takes a user and a password, and tries
various methods of comparing a password based on what the user supports:

=over 4

=item clear text password

If the user has clear a clear text password it will be compared directly.

=item crypted password

If UNIX crypt hashed passwords are supported, they will be compared using
perl's builtin C<crypt> function.

=item hashed password

If the user object supports hashed passwords, they will be used in conjunction
with L<Digest>.

=back

=head1 METHODS

=over 4

=item login $user, $password

Try to log a user in.

$user can be an ID or object. If it isa
L<Catalyst:::Plugin::Authentication::User> it will be used as is. Otherwise
C<< $c->get_user >> is used to retrieve it.

$password is a string.

=back

=cut



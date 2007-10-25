package Catalyst::Plugin::Authentication::Realm;

use strict;
use warnings;

use base qw/Class::Accessor::Fast/;

BEGIN {
    __PACKAGE__->mk_accessors(qw/store credential name config/);
};

sub new {
    my ($class, $realmname, $config, $app) = @_;

    my $self = { config => $config };
    bless $self, $class;
    
    $self->name($realmname);
    
    $app->log->debug("Setting up auth realm $realmname") if $app->debug;

    # use the Null store as a default
    if( ! exists $config->{store}{class} ) {
        $config->{store}{class} = '+Catalyst::Plugin::Authentication::Store::Null';
        $app->log->debug( qq(No Store specified for realm "$realmname", using the Null store.) );
    } 
    my $storeclass = $config->{'store'}{'class'};
    
    ## follow catalyst class naming - a + prefix means a fully qualified class, otherwise it's
    ## taken to mean C::P::A::Store::(specifiedclass)
    if ($storeclass !~ /^\+(.*)$/ ) {
        $storeclass = "Catalyst::Plugin::Authentication::Store::${storeclass}";
    } else {
        $storeclass = $1;
    }

    # a little niceness - since most systems seem to use the password credential class, 
    # if no credential class is specified we use password.
    $config->{credential}{class} ||= '+Catalyst::Plugin::Authentication::Credential::Password';

    my $credentialclass = $config->{'credential'}{'class'};
    
    ## follow catalyst class naming - a + prefix means a fully qualified class, otherwise it's
    ## taken to mean C::P::A::Credential::(specifiedclass)
    if ($credentialclass !~ /^\+(.*)$/ ) {
        $credentialclass = "Catalyst::Plugin::Authentication::Credential::${credentialclass}";
    } else {
        $credentialclass = $1;
    }
    
    # if we made it here - we have what we need to load the classes;
    Catalyst::Utils::ensure_class_loaded( $credentialclass );
    Catalyst::Utils::ensure_class_loaded( $storeclass );
    
    # BACKWARDS COMPATIBILITY - if the store class does not define find_user, we define it in terms 
    # of get_user and add it to the class.  this is because the auth routines use find_user, 
    # and rely on it being present. (this avoids per-call checks)
    if (!$storeclass->can('find_user')) {
        no strict 'refs';
        *{"${storeclass}::find_user"} = sub {
                                                my ($self, $info) = @_;
                                                my @rest = @{$info->{rest}} if exists($info->{rest});
                                                $self->get_user($info->{id}, @rest);
                                            };
    }
    
    ## a little cruft to stay compatible with some poorly written stores / credentials
    ## we'll remove this soon.
    if ($storeclass->can('new')) {
        $self->store($storeclass->new($config->{'store'}, $app, $self));
    } else {
        $app->log->error("THIS IS DEPRECATED: $storeclass has no new() method - Attempting to use uninstantiated");
        $self->store($storeclass);
    }
    if ($credentialclass->can('new')) {
        $self->credential($credentialclass->new($config->{'credential'}, $app, $self));
    } else {
        $app->log->error("THIS IS DEPRECATED: $credentialclass has no new() method - Attempting to use uninstantiated");
        $self->credential($credentialclass);
    }
    
    return $self;
}

sub find_user {
    my ( $self, $authinfo, $c ) = @_;

    my $res = $self->store->find_user($authinfo, $c);
    
    if (!$res) {
      if ($self->config->{'auto_create_user'} && $self->store->can('auto_create_user') ) {
          $res = $self->store->auto_create_user($authinfo, $c);
      }
    } elsif ($self->config->{'auto_update_user'} && $self->store->can('auto_update_user')) {
        $res = $self->store->auto_update_user($authinfo, $c, $res);
    } 
    
    return $res;
}

sub authenticate {
     my ($self, $c, $authinfo) = @_;

     my $user = $self->credential->authenticate($c, $self, $authinfo);
     if (ref($user)) {
         $c->set_authenticated($user, $self->name);
         return $user;
     } else {
         return undef;
     }
}

sub save_user_in_session {
    my ( $self, $c, $user ) = @_;

    $c->session->{__user_realm} = $self->name;
    
    # we want to ask the store for a user prepared for the session.
    # but older modules split this functionality between the user and the
    # store.  We try the store first.  If not, we use the old method.
    if ($self->store->can('for_session')) {
        $c->session->{__user} = $self->store->for_session($c, $user);
    } else {
        $c->session->{__user} = $user->for_session;
    }
}

sub from_session {
    my ($self, $c, $frozen_user) = @_;
    
    return $self->store->from_session($c, $frozen_user);
}


__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Realm - Base class for realm objects.

=head1 DESCRIPTION

=head1 CONFIGURATION

=over 4

=item class

=item auto_create_user

=item auto_update_user

=back

=head1 METHODS

=head2 new( )

=head2 find_user( )

=head2 authenticate( )

=head2 save_user_in_session( )

=head2 from_session( )

=back

=cut


package Catalyst::Authentication::Realm;
use Moose;
use String::RewritePrefix;
use Try::Tiny qw/ try catch /;
use namespace::autoclean;

foreach my $attr (qw/name config/) {
    has $attr => ( is => 'rw' );
}

has [qw/ auto_create_user auto_update_user /] => (
    is => 'ro',
    default => 0,
);

has __app => (
    is => 'ro',
    required => 1,
    handles => {
        __app_config => 'config',
        log => 'log',
    },
);
sub __auth_config { shift->__app_config->{'Plugin::Authentication'} }

has use_session => (
    is => 'ro',
    lazy => 1,
    default => sub {
        my $self = shift;
        exists $self->__auth_config->{use_sessuion} ? $self->__auth_config->{use_sessuion} : 1;
    },
);

foreach my $name (qw/ store credential /) {

    has "${name}_config" => (
        init_arg => $name,
        is => 'ro',
        default => sub { {} },
    );

    has "${name}_class" => (
        init_arg => undef,
        is => 'ro',
        lazy => 1,
        builder => "_build_${name}_class",
    );

    has $name => (
        init_arg => undef,
        is => 'rw',
        lazy => 1,
        default => sub {
            my $self = shift;
            my $get_class = "${name}_class";
            my $get_config = "${name}_config";
            $self->_build_store_or_credential($self->$get_class(), $self->$get_config)
        },
    );
}

sub _build_store_class {
    my $self = shift;
    $self->_load_class_with_deprecated(String::RewritePrefix->rewrite(
        { '' => 'Catalyst::Authentication::Store::', '+' => '' },
        $self->store_config->{class}
            || do {
                $self->log->debug( q(No Store specified for realm ") . $self->name . q(", using the Null store.) );
                'Null';
            },
    ));
}

sub _build_credential_class {
    my $self = shift;
    $self->_load_class_with_deprecated(String::RewritePrefix->rewrite(
        { '' => 'Catalyst::Authentication::Credential::', '+' => '' },
        $self->credential_config->{class} || 'Password'
    ));
}

sub _build_store_or_credential {
    my ($self, $class, $config) = @_;
    ## a little cruft to stay compatible with some poorly written stores / credentials
    ## we'll remove this soon.
    if ($class->can('new')) {
        return $class->new($config, $self->__app, $self);
    }
    $self->log->error("THIS IS DEPRECATED: $class has no new() method - Attempting to use uninstantiated");
    return $class;
}

## Add use_session config item to realm.

sub BUILDARGS {
    my ($class, $realmname, $config, $app) = @_;

    return {  %$config, __app => $app, name => $realmname, config => $config };
}

sub _load_class_with_deprecated {
    my ($self, $class) = @_;
    try {
        Catalyst::Utils::ensure_class_loaded( $class );
    }
    catch {
        # If the file is missing, then try the old-style fallback, 
        # but re-throw anything else for the user to deal with.
        die unless $@ =~ /^Can't locate/;
        $self->log->warn( qq(Class "$class" not found, trying deprecated ::Plugin:: style naming. ) );
        my $origclass = $class;
        $class =~ s/Catalyst::Authentication/Catalyst::Plugin::Authentication/;

        try { Catalyst::Utils::ensure_class_loaded( $class ); }
        catch {
            # Likewise this croak is useful if the second exception is also "not found",
            # but would be confusing if it's anything else.
            die $_ unless /^Can't locate/;
            Carp::croak "Unable to load class, " . $origclass . " OR " . $class .
                        " in realm " . $self->name;
        };
    };
    return $class;
}

sub BUILD {
    my ($self, $args) = @_;

    my $app = $self->__app;
    my $realmname = $self->name;
    my $config = $self->config;

    $app->log->debug("Setting up auth realm $realmname") if $app->debug;

    my $storeclass = $self->store_class;
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
    # Actually build the store and credential instances.
    $self->store;
    $self->credential;
}

sub find_user {
    my ( $self, $authinfo, $c ) = @_;

    my $res = $self->store->find_user($authinfo, $c);
    
    if (!$res) {
      if ($self->auto_create_user && $self->store->can('auto_create_user') ) {
          $res = $self->store->auto_create_user($authinfo, $c);
      }
    } elsif ($self->auto_update_user && $self->store->can('auto_update_user')) {
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

sub user_is_restorable {
    my ($self, $c) = @_;
    
    return unless
         $c->can('session')
         and $self->config->{'use_session'}
         and $c->session_is_valid;

    return $c->session->{__user};
}

sub restore_user {
    my ($self, $c, $frozen_user) = @_;
    
    $frozen_user ||= $self->user_is_restorable($c);
    return unless defined($frozen_user);

    my $user = $self->from_session( $c, $frozen_user );
    
    if ($user) {
        $c->_user( $user );
    
        # this sets the realm the user originated in.
        $user->auth_realm($self->name);
    } 
    else {
        $self->failed_user_restore($c) ||
            $c->error("Store claimed to have a restorable user, but restoration failed.  Did you change the user's id_field?");
	}
	 
    return $user;
}

## this occurs if there is a session but the thing the session refers to
## can not be found.  Do what you must do here.
## Return true if you can fix the situation and find a user, false otherwise
sub failed_user_restore {
	my ($self, $c) = @_;
	
	$self->remove_persisted_user($c);
	return;
}

sub persist_user {
    my ($self, $c, $user) = @_;
    
    if (
        $c->can('session')
        and $self->config->{'use_session'}
        and $user->supports("session") 
    ) {
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
    return $user;
}

sub remove_persisted_user {
    my ($self, $c) = @_;
    
    if (
        $c->can('session')
        and $self->config->{'use_session'}
        and $c->session_is_valid
    ) {
        delete @{ $c->session }{qw/__user __user_realm/};
    }    
}

## backwards compatibility - I don't think many people wrote realms since they
## have only existed for a short time - but just in case.
sub save_user_in_session {
    my ( $self, $c, $user ) = @_;

    return $self->persist_user($c, $user);
}

sub from_session {
    my ($self, $c, $frozen_user) = @_;
    
    return $self->store->from_session($c, $frozen_user);
}


__PACKAGE__->meta->make_immutable;

__END__

=pod

=head1 NAME

Catalyst::Authentication::Realm - Base class for realm objects.

=head1 DESCRIPTION

=head1 CONFIGURATION

=over 4

=item class

By default this class is used by
L<Catalyst::Plugin::Authentication|Catalyst::Plugin::Authentication> for all
realms. The class parameter allows you to choose a different class to use for
this realm. Creating a new Realm class can allow for authentication methods
that fall outside the normal credential/store methodology.

=item auto_create_user

Set this to true if you wish this realm to auto-create user accounts when the
user doesn't exist (most useful for remote authentication schemes).

=item auto_update_user

Set this to true if you wish this realm to auto-update user accounts after
authentication (most useful for remote authentication schemes).

=item use_session

Sets session usage for this particular realm - overriding the global use_sesion setting.


=back

=head1 METHODS

=head2 new( $realmname, $config, $app )

Instantiantes this realm, plus the specified store and credential classes.

=head2 store( )

Returns an instance of the store object for this realm.

=head2 credential( )

Returns an instance of the credential object for this realm.

=head2 find_user( $authinfo, $c )

Retrieves the user given the authentication information provided.  This 
is most often called from the credential.  The default realm class simply
delegates this call the store object.  If enabled, auto-creation and 
auto-updating of users is also handled here.

=head2 authenticate( $c, $authinfo)

Performs the authentication process for the current realm.  The default 
realm class simply delegates this to the credential and sets 
the authenticated user on success.  Returns the authenticated user object;

=head1 USER PERSISTENCE

The Realm class allows complete control over the persistance of users
between requests.  By default the realm attempts to use the Catalyst
session system to accomplish this.  By overriding the methods below
in a custom Realm class, however, you can handle user persistance in
any way you see fit.  

=head2 persist_user($c, $user)

persist_user is the entry point for saving user information between requests
in most cases this will utilize the session.  By default this uses the 
catalyst session system to store the user by calling for_session on the
active store.  The user object must be a subclass of 
Catalyst::Authentication::User.  If you have updated the user object, you 
must call persist_user again to ensure that the persisted user object reflects
your updates.

=head2 remove_persisted_user($c)

Removes any persisted user data.  By default, removes the user from the session.

=head2 user_is_restorable( $c )

Returns whether there is a persisted user that may be restored.  Returns
a token used to restore the user.  With the default session persistance
it returns the raw frozen user information.

=head2 restore_user($c, [$frozen_user])

Restores the user from the given frozen_user parameter, or if not provided,
using the response from $self->user_is_restorable();  Uses $self->from_session()
to decode the frozen user.

=head2 failed_user_restore($c)

If there is a session to restore, but the restore fails for any reason then this method 
is called. This method supplied just removes the persisted user, but can be overridden
if required to have more complex logic (e.g. finding a the user by their 'old' username).

=head2 from_session($c, $frozenuser )

Decodes the frozenuser information provided and returns an instantiated 
user object.  By default, this call is delegated to $store->from_session().

=head2 save_user_in_session($c, $user)

DEPRECATED.  Use persist_user instead.  (this simply calls persist_user)

=cut

package Catalyst::Plugin::Authentication::Credential::Wrapper;

use strict;
use warnings;

sub new {
    my ($myclass, $hash, $app) = @_;
    

    if (!exists($hash->{'class'})) {
        Carp::croak "Couldn't setup a wrapped Credential, no module specified";
    }
    my $data = {};
    my $wrappedclass = $hash->{'class'};
    my $authroutine = $hash->{'authroutine'} ||= 'authenticate';
    $data->{authroutine} = $wrappedclass->can($authroutine);
    
    if (!$data->{'authroutine'}) {
        Carp::croak "Couldn't set up a wrapped Credential, auth sub: $authroutine was not found";
    }
    
    bless $data, $myclass;   
}

sub authenticate {
    my ($self, $c, $store, $authinfo) = @_;
    
    return $self->{'authroutine'}->($c, $store, $authinfo);
}

__PACKAGE__;

__END__
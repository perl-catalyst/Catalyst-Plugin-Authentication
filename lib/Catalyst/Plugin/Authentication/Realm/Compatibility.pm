package Catalyst::Plugin::Authentication::Realm::Compatibility;

use strict;
use warnings;
use base qw/Catalyst::Plugin::Authentication::Realm/;


## very funky - the problem here is that we can't do real realm initialization
## but we need a real realm object to function.  So - we kinda fake it - we 
## create an empty object - 
sub new {
    my ($class, $realmname, $config, $app) = @_;
    
    my $self = { config => $config };
    bless $self, $class;
    
    $self->name($realmname);
    
    return $self;
}

__PACKAGE__;

__END__
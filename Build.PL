use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name        => 'Catalyst::Plugin::Authentication',
    requires           => {
        'perl'                      => '5.8.1',
        'Catalyst'                  => '5.49',
        'Class::Inspector'          => 0,
        'Catalyst::Plugin::Session' => '0.10',
        'Tie::RefHash'              => '1.35',
    },
    create_readme => 1,
    sign          => 1,
);
$build->create_build_script;


#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Store;

use strict;
use warnings;

sub get_user { die "virtual" }

sub user_supports { die "virtual" }

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Store - 

=head1 SYNOPSIS

	use Catalyst::Plugin::Authentication::Store;

=head1 DESCRIPTION

=cut



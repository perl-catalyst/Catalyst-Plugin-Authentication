#!/usr/bin/perl

use strict;
use warnings;

use Test::More 'no_plan';

use lib 't/lib';
use Catalyst::Test qw/AuthTestApp/;

ok(get("/moose"), "get ok");

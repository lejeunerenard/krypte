#!/usr/bin/env perl

use strict;
use warnings;

use FindBin;

use Test::More tests => 1;
use Test::Deep; # (); # uncomment to stop prototype errors
use Test::Exception;

use_ok 'Krypte';

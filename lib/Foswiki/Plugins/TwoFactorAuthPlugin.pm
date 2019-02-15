# Plugin for Foswiki - The Free and Open Source Wiki, https://foswiki.org/
#
# TwoFactorAuthPlugin is Copyright (C) 2018-2019 Michael Daum http://michaeldaumconsulting.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details, published at
# http://www.gnu.org/copyleft/gpl.html

package Foswiki::Plugins::TwoFactorAuthPlugin;

use strict;
use warnings;

use Foswiki::Func ();
use Foswiki::Plugins::JQueryPlugin ();

our $VERSION = '1.00';
our $RELEASE = '15 Feb 2019';
our $SHORTDESCRIPTION = 'Two-factor authentication solution based on one-time passwords';
our $NO_PREFS_IN_TOPIC = 1;
our $core;

sub initPlugin {
  my ($topic, $web, $user) = @_;

  Foswiki::Func::registerTagHandler('OTPINFO', sub { return getCore()->OTPINFO(@_); });

  Foswiki::Func::registerRESTHandler('verify', sub { return getCore()->restVerify(@_); },
    authenticate => 1,
    validate => 1,
    http_allow => 'GET,POST',
  );

  Foswiki::Func::registerRESTHandler('activate', sub { return getCore()->restActivate(@_); },
    authenticate => 1,
    validate => 1,
    http_allow => 'GET,POST',
  );

  Foswiki::Func::registerRESTHandler('deactivate', sub { return getCore()->restDeactivate(@_); },
    authenticate => 1,
    validate => 1,
    http_allow => 'GET,POST',
  );

  getCore();

# unless (Foswiki::Func::getContext()->{login}) {
#   my $isProtected = Foswiki::Func::isTrue(Foswiki::Func::getPreferencesValue("TWOFACTORAUTH_PROTECTION"), 0);
# 
#   if ($isProtected) {
#     if (getCore()->isEnabled()) {
#       my $url = Foswiki::Func::getScriptUrl($web, $topic, "login", foswiki_origin => packRequest());
#       Foswiki::Func::redirectCgiQuery(undef, $url);
#     } else {
#       # access violation
#     }
#   }
# }

  unless ($Foswiki::cfg{LoginManager} =~ /TwoFactorAuth/) {
    Foswiki::Func::writeWarning("TwoFactorAuthPlugin disabled as you don't seem to have set the LoginManager accordingly");
    return 0;
  }

  return 1;
}

sub packRequest {
  my $request = shift;

  $request ||= Foswiki::Func::getRequestObject();
  return ($request->method() || 'UNDEFINED').':'.$request->action().':'.$request->uri;
}

sub getCore {
  unless (defined $core) {
    require Foswiki::Plugins::TwoFactorAuthPlugin::Core;
    $core = Foswiki::Plugins::TwoFactorAuthPlugin::Core->new();
  }
  return $core;
}

sub finishPlugin {
  return unless $core;
  $core->finish();
  undef $core;
}

1;

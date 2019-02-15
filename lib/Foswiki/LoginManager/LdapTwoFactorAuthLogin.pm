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

package Foswiki::LoginManager::LdapTwoFactorAuthLogin;

use strict;
use warnings;
use Assert;
use Unicode::Normalize;
use Foswiki::Sandbox ();
use Foswiki::Contrib::LdapContrib ();

use Foswiki::LoginManager::TwoFactorAuthLogin ();
our @ISA = ('Foswiki::LoginManager::TwoFactorAuthLogin');

=begin TML

---++ ClassMethod new($session)

Construct the <nop>LdapTwoFactorAuthLogin object

Note that we are copying LdapTemplateLogin here just to prevent multiple inheritance.

=cut

sub new {
  my ($class, $session) = @_;

  my $this = bless($class->SUPER::new($session), $class);

  $this->{ldap} = Foswiki::Contrib::LdapContrib::getLdapContrib($session);
  return $this;
}

=begin TML

---++ ObjectMethod loadSession()

Load the session, sanitize the login name and make sure its user information are already
cached.

=cut

sub loadSession {
  my $this = shift;

  my $authUser = $this->SUPER::loadSession(@_);
  $authUser = Foswiki::Sandbox::untaintUnchecked($authUser);

  if ($this->{ldap}->getWikiNameOfLogin($authUser)) {
    $authUser =  $this->{ldap}->loadSession($authUser);
  } else {
    # try email
    my $logins = $this->{ldap}->getLoginOfEmail($authUser);
    if (defined $logins && scalar(@$logins)) {
      $authUser = $logins->[0];
      $authUser =  $this->{ldap}->loadSession(shift @$logins);
    }
  }

  return $authUser;
}

1;


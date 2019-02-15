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

package Foswiki::Plugins::TwoFactorAuthPlugin::Core;

use strict;
use warnings;

use Foswiki::Func ();
use URI::Escape qw(uri_escape);
use Convert::Base32 qw( encode_base32 decode_base32);

use constant TRACE => 0; # toggle me

sub new {
  my $class = shift;

  my $this = bless({
    #logo => 'https://foswiki.org/pub/System/ProjectLogos/foswiki-logo-icon.png', #TODO: make configurable
    logo => $Foswiki::cfg{TwoFactorAuthPlugin}{LogoUrl} // 'https://foswiki.org/pub/System/ProjectLogos/foswiki-logo-large.png',
    maxAttempts => $Foswiki::cfg{TwoFactorAuthPlugin}{MaxAttempts} // 4,
    attemptsPeriod => $Foswik::cfg{TwoFactorAuthPlugin}{AttemptsPeriod} // 30,
    issuer => $Foswik::cfg{TwoFactorAuthPlugin}{Issuer} // Foswiki::Func::getPreferencesValue("WIKITOOLNAME"),
    filePerms => $Foswiki::cfg{RCS}{filePermission} || 0600,
    @_
  }, $class);

  my $wikiName = Foswiki::Func::getWikiName();
  if ($this->isEnabled() && $wikiName ne $Foswiki::cfg{DefaultUserWikiName}) {
    _writeDebug("two-factor authentication is enabled for $wikiName");
    Foswiki::Func::getContext()->{"TwoFactorAuthenticationEnabled"} = 1;
  } else {
    _writeDebug("two-factor authentication is NOT enabled for $wikiName");
  }

  return $this;
}

sub finish {
  my $this = shift;

  $this->saveUserData();

  undef $this->{_handler};
  undef $this->{_json};
  undef $this->{_data};
}

sub saveUserData {
  my ($this) = @_;

  # save all data
  foreach my $wikiName (keys %{$this->{_data}}) {
    next if $wikiName eq $Foswiki::cfg{DefaultUserWikiName};
    my $data = $this->getUserData($wikiName);

    if ($data->{_isModified}) {
      delete $data->{_isModified};
      my $fileName = _getDataFileName($wikiName);
      Foswiki::Func::saveFile($fileName, $this->json->encode($data));

      chmod $this->{filePerms}, $fileName; # for security reasons
    }
  }
}

sub getUserData {
  my ($this, $wikiName) = @_;

  $wikiName ||= Foswiki::Func::getWikiName();

  unless (defined $this->{_data}{$wikiName}) {
    my $file = _getDataFileName($wikiName);

    my $data;
    if (-e $file) {
      $data = Foswiki::Func::readFile($file);
    } else {
      $data = '{}';
    }

    $this->{_data}{$wikiName} = $this->json->decode($data);
  }

  return $this->{_data}{$wikiName};
}

sub secret {
  my ($this, $wikiName) = @_;

  my $data = $this->getUserData($wikiName);
  unless (defined $data->{secret}) {
    $data->{secret} = _generateSecret();
    $data->{_isModified} = 1;
  }

  return $data->{secret};
}


sub restActivate {
  my ($this, $session, $subject, $verb, $response) = @_;

  _writeDebug("called restActivate()");

  my $request = Foswiki::Func::getRequestObject();
  my $code = $request->param("code");

  my $isOk = $this->verify($code);

  $this->activate() if $isOk;

  return $isOk?"true":"false";;
}

sub restDeactivate {
  my ($this, $session, $subject, $verb, $response) = @_;

  _writeDebug("called restDeactivate()");

  $this->deactivate();

  return "true";
}

sub restVerify {
  my ($this, $session, $subject, $verb, $response) = @_;

  _writeDebug("called restVerify()");

  my $request = Foswiki::Func::getRequestObject();
  my $code = $request->param("code");

  my $isOk = $this->verify($code);

  return $isOk ? "true":"false";
}

sub checkAttempts {
  my ($this, $wikiName) = @_;

  _writeDebug("called checkAttempts()");
  return 1 unless $this->{maxAttempts} && $this->{attemptsPeriod};

  my $data = $this->getUserData($wikiName);
  my $now = time();

  $data->{attemptTime} ||= $now;
  my $since = $now - $data->{attemptTime};

  $data->{numAttempts} ||= 0;
  $data->{numAttempts} = 0 if $since >= $this->{attemptsPeriod};

  _writeDebug("numAttempts=$data->{numAttempts}, attemptTime=$data->{attemptTime}, since=$since");

  if ($data->{numAttempts} >= $this->{maxAttempts}) {
    _writeDebug("WARNING: user tried more than $this->{maxAttempts} times to verify the token");
    return 0;
  }

  $data->{numAttempts}++;
  $data->{attemptTime} = $now;
  $data->{_isModified} = 1;

  return 1;  
}

sub deleteAttemptsCheck {
  my ($this, $wikiName) = @_;

  _writeDebug("called deleteAttemptsCheck()");
  my $data = $this->getUserData($wikiName);

  delete $data->{numAttempts};
  delete $data->{attemptTime};
  $data->{_isModified} = 1;
}

sub OTPINFO {
  my ($this, $session, $params, $topic, $web) = @_;

  _writeDebug("called OTPINFO()");
  my $result = $params->{_DEFAULT} || $params->{format} // '$otpauth';
  my $issuer = $params->{issuer} // $this->{issuer};
  my $keyId = $params->{keyId};

  unless (defined $keyId) {
    my $wikiName = Foswiki::Func::getWikiName();
    my $loginName = Foswiki::Func::wikiToUserName($wikiName);
    $keyId = $loginName;
  }

  my $secret = $this->secret();
  my @groups = ();
  for (my $i = 0; $i < length($secret); $i += 4) {
    push @groups, substr($secret, $i, 4);
  }
  my $group = join(" ", @groups);

  my $otpauth = 'otpauth://totp/' .
          uri_escape($issuer) . ':' . uri_escape($keyId) .
          '?secret=' . $secret . 
          '&issuer=' . uri_escape($issuer) .
          '&image=' . uri_escape($this->{logo});
  
  $result =~ s/\$otpauth/$otpauth/g;
  $result =~ s/\$issuer/$issuer/g;
  $result =~ s/\$keyid/$keyId/g;
  $result =~ s/\$secret/$group/g;

  return $result;
}

sub json {
  my $this = shift;

  unless ($this->{_json}) {
    $this->{_json} = JSON->new->pretty(1);
  }

  return $this->{_json};
}

sub auth {
  my $this = shift;

  unless ($this->{_handler}) {
    require Authen::OATH;
    $this->{_handler} = Authen::OATH->new();
  }

  return $this->{_handler};
}

sub verify {
  my ($this, $code, $wikiName) = @_;

  _writeDebug("called verify()");

  return 0 unless $this->checkAttempts($wikiName);

  my $thisCode = $this->getCode($wikiName);

  # normalize a bit
  $code =~ s/ //g;

  _writeDebug("verify($code) ... this code = $thisCode");

  my $isOk = $code eq $thisCode ? 1 : 0;

  $this->deleteAttemptsCheck($wikiName) if $isOk;

  return $isOk;
}

sub getCode {
  my ($this, $wikiName) = @_;
  
  return $this->auth->totp(decode_base32($this->secret($wikiName)));
}

sub activate {
  my ($this, $wikiName) = @_;

  my $data = $this->getUserData($wikiName);
  $data->{enabled} = 1;
  $data->{_isModified} = 1;
}

sub deactivate {
  my ($this, $wikiName) = @_;

  my $data = $this->getUserData($wikiName);
  $data->{enabled} = 0;
  delete $data->{secret};

  $data->{_isModified} = 1;
}

sub isEnabled {
  my ($this, $wikiName) = @_;

  my $data = $this->getUserData($wikiName);
  return $data->{enabled} ? 1:0;
}

sub _generateSecret {
  my @chars = ( 'A' .. 'Z', 0 .. 9 );
  my $str = join('', @chars[ map { rand( scalar(@chars) ) } 1 .. 16]);
  return uc(encode_base32($str));
}

sub _writeDebug {
  return unless TRACE;
  #Foswiki::Func::writeDebug("TwoFactorAuthPlugin::Core - $_[0]");
  print STDERR "TwoFactorAuthPlugin::Core - $_[0]\n";
}

sub _getDataFileName {
  my $wikiName = shift;

  $wikiName ||= Foswiki::Func::getWikiName();
  return Foswiki::Func::getWorkArea("TwoFactorAuthPlugin") . "/" . $wikiName . ".txt";
}

1;

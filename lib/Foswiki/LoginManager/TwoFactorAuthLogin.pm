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

package Foswiki::LoginManager::TwoFactorAuthLogin;

use strict;
use warnings;
use Assert;
use Unicode::Normalize;

use Foswiki::Func ();
use Foswiki::LoginManager ();
our @ISA = ('Foswiki::LoginManager::TemplateLogin');
use Encode ();

use constant TRACE => 0; # toggle me

our $SESSION_KEY = "_TWOFACTORAUTH";

# SMELL
use Foswiki::LoginManager::TemplateLogin ();
*_packRequest = \&Foswiki::LoginManager::TemplateLogin::_packRequest;
*_unpackRequest = \&Foswiki::LoginManager::TemplateLogin::_unpackRequest;

=begin TML

---++ ClassMethod new($session)

Construct the <nop>TwoFactorAuthLogin object

=cut

sub new {
  my ($class, $session) = @_;

  my $this = bless($class->SUPER::new($session), $class);

  # add session key to secret keys so that it cannot be accseed by %SESSION_VARIABLE%
  $Foswiki::LoginManager::secretSK{$SESSION_KEY} = 1;

  return $this;
}

=pod

---++ ObjectMethod login($query)

main entrance point 

=cut

sub login {
  my ($this, $query) = @_;

  _writeDebug("### called login()");

  my $origin = $query->param('foswiki_origin');
  my ($origurl, $origmethod, $origaction) = _unpackRequest($origin);
  $origurl =~ s/[\?&;]logout=(1|on|yes)// if $origurl;    # don't propagate logout

  my $tmpl = Foswiki::Func::readTemplate("login");
  my $banner = '';
  my $note = '';
  my $topic = $this->{session}{topicName};
  my $web = $this->{session}{webName};
  my $isOk;

  my $loginName = $query->param('username') || '';
  my $accessCode = $query->param('accesscode') || '';

  # determin which state we are in:
  # loginStage = 0: check the first factor
  # loginStage = 1: check the second factor
  my $loginStage = ($this->getLoginStage() && $loginName)?1:0;

  # called for another code check even though logged in already, so skip to the second stage.
  if (Foswiki::Func::getContext()->{authenticated}) {
    $loginName = $this->{session}{user};
    $loginStage = 1;
  }

  #_writeDebug("loginName=$loginName, loginStage=$loginStage, accessCode=$accessCode");

  # present dialog for first stage
  if (!$loginName) {
    _writeDebug("first stage");
    $banner = Foswiki::Func::expandTemplate('LOG_IN_BANNER');

    $this->setLoginStage(0);
  }

  # present dialog for second stage
  elsif ($loginName && $loginStage && !$accessCode) {
    my $wikiName = Foswiki::Func::userToWikiName($loginName, 1);
    if ($this->authManager->isEnabled($wikiName)) {
      _writeDebug("second stage");
      $tmpl = Foswiki::Func::readTemplate("twofactorlogin");
      $banner = Foswiki::Func::expandTemplate('LOG_IN_BANNER');
    } else {
      _writeDebug("no 2fa enabled ... skipping second stage");
      $isOk = 1;
    }
    $this->setLoginStage(1);
  }

  # check first factor
  elsif ($loginName && !$loginStage) {
    _writeDebug("checking first factor");
    $isOk = $this->checkFirstFactor($query);

    if ($isOk) {
      my $wikiName = Foswiki::Func::userToWikiName($loginName, 1);
      if ($this->authManager->isEnabled($wikiName)) {
        # present dialog for second stage
        $tmpl = Foswiki::Func::readTemplate("twofactorlogin");
        $banner = Foswiki::Func::expandTemplate('LOG_IN_BANNER');
      } else {
        _writeDebug("no 2fa enabled ... skipping second stage");
        $loginStage = 1;
      }

      $this->setLoginStage(1);
    } else {
      $banner = Foswiki::Func::expandTemplate('UNRECOGNISED_USER');
      $this->setLoginStage(0);
    }
  }

  # check second factor
  elsif ($loginName && $loginStage && $accessCode) {
    _writeDebug("checking second factor");
    $isOk = $this->checkSecondFactor($query);

    unless ($isOk) {
      $tmpl = Foswiki::Func::readTemplate("twofactorlogin");
      $banner = Foswiki::Func::expandTemplate('UNRECOGNISED_USER');
    }

    $this->setLoginStage(1); # stay in second stage
  }

  _writeDebug("isOk=".($isOk//'undef'));

  # propagate login name
  $tmpl =~ s/%LOGINNAME%/$loginName/go;

  # Eat these so there's no risk of accidental passthrough
  $this->{session}{request}->delete('validation_key', 'foswiki_origin', 'sudo', 'username', 'password', 'accesscode');

  # go to next stage if the current one is valid
  if (defined $isOk) {
    if ($isOk) {

      # exit when all stages passed
      if ($loginStage) {

        $this->userLoggedIn($loginName);

        $this->{session}->logger->log({
            level => 'info',
            action => 'login',
            webTopic => $web . '.' . $topic,
            extra => "AUTHENTICATION SUCCESS - $loginName - "
          }
        );

        # remember result in session ... what for ... SMELL
        $this->setSessionValue('VALIDATION', $isOk);

        if (!$origurl || $origurl eq $query->url()) {
          $origurl = $this->{session}->getScriptUrl(0, 'view', $web, $topic);
        } else {

          # Unpack params encoded in the origurl and restore them
          # to the query. If they were left in the query string they
          # would be lost if we redirect with passthrough.
          # First extract the params, ignoring any trailing fragment.
          if ($origurl =~ s/\?([^#]*)//) {
            foreach my $pair (split(/[&;]/, $1)) {
              if ($pair =~ m/(.*?)=(.*)/) {
                $query->param($1, TAINT($2));
              }
            }
          }

          # Restore the action too
          $query->action($origaction) if $origaction;
        }

        # Restore the method used on origUrl so if it was a GET, we
        # get another GET.
        $query->method($origmethod);
        $this->{session}->redirect($origurl, 1);
        return;
      }

    } else {
      $this->{session}->logger->log({
          level => 'info',
          action => 'login',
          webTopic => $web . '.' . $topic,
          extra => "AUTHENTICATION FAILURE - $loginName - ",
        }
      );
    }
  }

  # Truncate the path_info at the first quote
  my $path_info = $query->path_info();
  if ($path_info =~ m/['"]/g) {
    $path_info = substr($path_info, 0, ((pos $path_info) - 1));
  }

  # Set session preferences that will be expanded when the login
  # template is instantiated
  $origurl ||= '';
  $this->{session}{prefs}->setSessionPreferences(
    FOSWIKI_ORIGIN => Foswiki::entityEncode(_packRequest($origurl, $origmethod, $origaction)),

    # Path to be used in the login form action.
    # Could have used %ENV{PATH_INFO} (after extending {AccessibleENV})
    # but decided against it as the path_info might have been rewritten
    # from the original env var.
    PATH_INFO => Foswiki::urlEncode(NFC(Foswiki::decode_utf8($path_info))),
    BANNER => $banner,
    NOTE => $note,
    ERROR => $this->{_error},
  );

  my $topicObject = Foswiki::Meta->new($this->{session}, $web, $topic);
  $tmpl = $topicObject->expandMacros($tmpl);
  $tmpl = $topicObject->renderTML($tmpl);
  $tmpl =~ s/<nop>//g;

  $this->{session}{response}->status(200);
  $this->{session}->writeCompletePage($tmpl);
}

=pod

---++ ObjectMethod checkFirstFactor($query) -> $boolean

first stage of authentication. sets this->{_error} message on a login failure

=cut

sub checkFirstFactor {
  my ($this, $query) = @_;

  my $loginName = $query->param('username');
  my $loginPass = $query->param('password');

  return 0 unless $loginName && $loginPass;

  my $users = $this->{session}{users};
  my $isOk = $users->checkPassword($loginName, $loginPass);
  $this->{_error} = $users->passwordError($loginName);

  if (!$isOk
    && $Foswiki::cfg{TemplateLogin}{AllowLoginUsingEmailAddress}
    && ($loginName =~ $Foswiki::regex{emailAddrRegex}))
  {

    # try email addresses if it is one
    my $cuidList = $users->findUserByEmail($loginName);
    foreach my $cuid (@$cuidList) {
      my $login = $users->getLoginName($cuid);

      $isOk = $users->checkPassword($login, $loginPass);
      if ($isOk) {
        $loginName = $login;
        last;
      }
    }
  }

  my $remember = $query->param('remember');
  $this->setSessionValue('REMEMBER' . $remember) if defined $remember && $isOk;

  return $isOk;
}

=pod

---++ ObjectMethod checkSecondFactor($query) -> $boolean

second stage of authentication

=cut

sub checkSecondFactor {
  my ($this, $query) = @_;

  my $loginName = $query->param('username');
  return 0 unless $loginName;

  my $wikiName = Foswiki::Func::userToWikiName($loginName, 1);

  return 1 unless $this->authManager->isEnabled($wikiName);

  my $accessCode = $query->param('accesscode');
  return 0 unless $accessCode;

  return $this->authManager->verify($accessCode, $wikiName);
}

=pod

---++ ObjectMethod getLoginStage()

get current stage of authentication

=cut

sub getLoginStage {
  my $this = shift;

  my $val = $this->getSessionValue($SESSION_KEY) || 0;
  Foswiki::Func::clearSessionValue($SESSION_KEY); # consume it

  return $val;
}

=pod

---++ ObjectMethod setLoginStage()

set stage of authentication

=cut

sub setLoginStage {
  my ($this, $state) = @_;

  $state ||= 0;

  $this->setSessionValue($SESSION_KEY, $state);
}

=pod

---++ ObjectMethod authManager()

returns the auth manager

=cut

sub authManager {
  my $this = shift;
  require Foswiki::Plugins::TwoFactorAuthPlugin;
  return Foswiki::Plugins::TwoFactorAuthPlugin->getCore();
}


sub _writeDebug {
  return unless TRACE;
  print STDERR "TwoFactorAuthLogin - $_[0]\n";
}

1;

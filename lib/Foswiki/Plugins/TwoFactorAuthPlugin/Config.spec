# ---+ Extensions
# ---++ TwoFactorAuthPlugin
# This is the configuration used by the <b>TwoFactorAuthPlugin</b>.

# **NUMBER**
# Number of login attempts allowed in a certain period of time.
$Foswiki::cfg{TwoFactorAuthPlugin}{MaxAttempts} = 4;

# **NUMBER**
# Period of time within which a certain amount of login attempts are allowed.
$Foswiki::cfg{TwoFactorAuthPlugin}{AttemptsPeriod} = 30;

# **STRING**
# Logo to be displayed in the 2FA token app on your mobile device. 
# Note that the url of this logo has to be accessible to the outside world, i.e. your mobile device
# when the token is initiated.
$Foswiki::cfg{TwoFactorAuthPlugin}{LogoUrl} = 'https://foswiki.org/pub/System/ProjectLogos/foswiki-logo-large.png';

# **STRING**
# Name of the site associated with the one-time password on your mobile device.
# This defaults to the WIKITOOLNAME if left undefined.
$Foswiki::cfg{TwoFactorAuthPlugin}{Issuer} = '';

1;

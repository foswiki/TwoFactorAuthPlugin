# ---+ Extensions
# ---++ TwoFactorAuthPlugin
# This is the configuration used by the <b>TwoFactorAuthPlugin</b>.

# **NUMBER**
$Foswiki::cfg{TwoFactorAuthPlugin}{MaxAttempts} = 4;

# **NUMBER**
$Foswiki::cfg{TwoFactorAuthPlugin}{AttemptsPeriod} = 30;

# **STRING**
$Foswiki::cfg{TwoFactorAuthPlugin}{LogoUrl} = 'https://foswiki.org/pub/System/ProjectLogos/foswiki-logo-large.png',

# **STRING**
$Foswik::cfg{TwoFactorAuthPlugin}{Issuer} = '';

1;

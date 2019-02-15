/*
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2018-2019 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

*/

/*global foswikiStrikeOne:false */

"use strict";
jQuery(function($) {
  $(".twoFactorDisableForm").livequery(function() {
    var $form = $(this), 
        redirectElem = $form.find("input[name=redirect]");

    $form.ajaxForm({
      beforeSerialize: function() {
        if (typeof(StrikeOne) !== 'undefined') {
          foswikiStrikeOne($form[0]);
        }
      },
      error: function(xhr) {
        $.pnotify({
          type: "error",
          title: "Error",
          text: xhr.responseText
        });
      },
      success: function(data) {
        if (data === 'true') {
          if (redirectElem.length) {
            window.setTimeout(function() {
              window.location.href = redirectElem.val();
            }, 1000);
          }
        } else {
          $.pnotify({
            type: "error",
            title: "Error",
            text: data
          });
        }
      }
    });
  });

});

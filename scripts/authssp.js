var authssp = { };

authssp.config = authssp_config;

authssp.initialize = function() {
  authssp.lang = LANG.plugins.authssp;
  if (!authssp.config.current) {
    return;
  }
  if (authssp.config.current != 'ask') {
    return;
  }
  var ret = confirm(authssp.lang.question);
  if (ret) {
    ret = 'persistentlogin';
  } else {
    ret = '';
  }

  jQuery.post(
    DOKU_BASE + 'lib/exe/ajax.php',
    { 'value'  : ret,
      'call'   : 'setpersistentlogin',
      'sectok' : authssp.config.sectok
    }
  );
};

jQuery(document).ready(authssp.initialize);


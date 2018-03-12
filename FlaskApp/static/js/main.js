$(function() {
      $('#register-submit').prop( "disabled", true );
      $('#login-form-link').click(function(e) {
        set_login_active();
      });
      $('#register-form-link').click(function(e) {
        set_register_active();
      });

      if (curContext == "login") {
        set_login_active();
      } else {
        set_register_active();
      }
  });

  function enableRegister() {
    $('#register-submit').prop( "disabled", false );
  }
  function set_login_active() {
    $("#login-form").delay(100).fadeIn(100);
    $("#register-form").fadeOut(100);
    $('#register-form-link').removeClass('active');
    $('#login-form-link').addClass('active');
  }

  function set_register_active() {
    $("#register-form").delay(100).fadeIn(100);
    $("#login-form").fadeOut(100);
    $('#login-form-link').removeClass('active');
    $('#register-form-link').addClass('active');
  }

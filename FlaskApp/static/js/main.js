$(function() {
      // Submit button disabled till the re-Captcha is validated
      $('#register-submit').prop( "disabled", true );

      // Click handlers
      $('#login-form-link').click(function(e) {
        set_login_active();
      });
      $('#register-form-link').click(function(e) {
        set_register_active();
      });

      // Inflate widgets depending on the current context. This is set by jinja
      // template
      if (curContext == "login") {
        set_login_active();
      } else {
        set_register_active();
      }
  });


  // re-Captcha callback to enable the submit button after human confirmation
  function enableRegister() {
    $('#register-submit').prop( "disabled", false );
  }

  // stub function to set login widget active
  function set_login_active() {
    $("#login-form").delay(100).fadeIn(100);
    $("#register-form").fadeOut(100);
    $('#register-form-link').removeClass('active');
    $('#login-form-link').addClass('active');
  }

  // stub function to set register widget active
  function set_register_active() {
    $("#register-form").delay(100).fadeIn(100);
    $("#login-form").fadeOut(100);
    $('#login-form-link').removeClass('active');
    $('#register-form-link').addClass('active');
  }

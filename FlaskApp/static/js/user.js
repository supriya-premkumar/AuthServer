$(function(){
  // Language click icon handlers. These will POST to respective respective
  // endpoints and collect reponses. On session valid it alerts with a
  // unique greeting. Once the token is no longer valid, it redirects to the Login
  // page to reauthenticate

  // go REST POSTer
  $('#go').click(function(e) {
    var tok = {"token":accessToken};
    $.ajax({
       url: "https://supriya.tech:8001",
       type: "POST",
       data: JSON.stringify(tok),
       crossDomain: true,
       dataType:'json',
       statusCode: {
         200: function(response) {
           alert(response["Message"]);
         },
         401: function(response) {
           alert("Session Expired, Please Login:");
           window.location.replace("/");
         },
         404: function(response) {
           alert("User not found. Please register");
           window.location.replace("/");
         },
       },
       error: function (xhr, status) {
         console.log(status);
       }
   });
  });

  // python REST POSTer
  $('#py').click(function(e) {
    var tok = {"token":accessToken};
    $.ajax({
       url: "https://supriya.tech:8000",
       type: "POST",
       data: JSON.stringify(tok),
       crossDomain: true,
       dataType: 'json',
       statusCode: {
         200: function(response) {
           alert(response["Message"]);
         },
         401: function(response) {
           alert("Session Expired, Please Login:");
           window.location.replace("/");
         },
         404: function(response) {
           alert("User not found. Please register");
           window.location.replace("/");
         },
       },
       error: function (xhr, status) {
         console.log(status);
       }
   });
  });
});

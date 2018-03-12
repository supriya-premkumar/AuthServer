$(function(){
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

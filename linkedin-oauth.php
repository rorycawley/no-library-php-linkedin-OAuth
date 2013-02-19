<?php
// Use an OAuth Library!
// Read this if you want to learn about this code
// http://blog.thewebcafes.com/post/1502524959/php-step-by-step-oauth-for-dummies-based-on-linkedin
// http://blog.thewebcafes.com/post/1530566947/php-step-by-step-oauth-for-dummies-based-on-linkedin
// http://blog.thewebcafes.com/post/2874607539/php-step-by-step-oauth-for-dummies-based-on-linkedin
// https://developer.linkedin.com/documents/authentication
// http://oauth.net/documentation/getting-started/
// http://hueniverse.com/oauth/

define('LINKEDIN_KEY', 'API KEY');
define('LINKEDIN_SECRET', 'SECRET API KEY'); 


if (strlen(session_id()) < 1) {
    session_start();
}

// 1. request permission from the user to user their linkedin identity to access linkedin api, and handle errors

// Developers can leverage linkedin member identity to deliver seamless and rewarding experiences to LinkedIn members
// * Supported use cases are:
// registration and sign-in - allow members to signin to your website with their LinkedIn identity
// public identity - allow users to authenticate with your site and light up LinkedIn profile plugins
// activity sharing - from your site, allow members to share their activity using sharing api
// professional context - leverage their network for communications and collaboration on your site

// The application will act on behalf of a member, it's important that:
// *The application will need to identify the member
// *The application will protect the member's privacy
// *Linkedin knows which application and which member makes the request

// To accomplish this LinkedIn uses Oauth 1.0a to give your app authorised access to the APIs
// OAuth is a standard to negociating developer authorisation and granting access on behalf of linkedin members
// to perform API requests

// OAuth is:
// 1. Ask for temporary credentials (request token)
// 2. Redirect user to a login, to authorise temporary credentials to be associated with the LinkedIn account
// 3. The credentials get upgraded to permanent credentials (access token) and app can use this to invoke LinkedIn API
// on behalf of the user (access tokens last for 60 days and then expire)
// A call made on an expired access token is:
//<error>
//  <status>401</status>
//  <timestamp>1343687838351</timestamp>
//  <request-id>10FMEGSWWN</request-id>
//  <error-code>0</error-code>
//  <message>[unauthorized]. Expired access token. Timestamp: 1343685790676</message>
//</error>
// you can choose to refresh the access token on day 58 before it expires, as long as the user is 
// still logged-in to Linkedin, and get a new access token for another 60 days
// By catching 401 Unauthorized exceptions in all your calls you'll provide the coverage you need 
// in your application to handle expired tokens. It's good practice to design and develop your 
// application in anticipation that with any request you could potentially have an invalid access token. 
// LinkedIn always returns a 401 Unauthorized error as described above. A simple re-authentication 
// is usually all that is required to make API calls again.

// it's highly advisable to use a linkedin library since this is the biggest stumbling block
// here we won't use one just to know what's really involved

// when the api key is created you specify what profile information will be available to the app once the
// member gives it authorisation
// it's possible to pass additional permission scope parameters when obtaining the request token e.g.:
// https://api.linkedin.com/uas/oauth/requestToken?scope=r_basicprofile+r_emailaddress


function curPageURL() {
 $pageURL = 'http';
 if ($_SERVER["HTTPS"] == "on") {$pageURL .= "s";}
 $pageURL .= "://";
 if ($_SERVER["SERVER_PORT"] != "80") {
  $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];
 } else {
  $pageURL .= $_SERVER["SERVER_NAME"].$_SERVER["REQUEST_URI"];
 }
 return $pageURL;
}

// logfile setup
$log_file = $_SERVER['DOCUMENT_ROOT']."/htdocs/log.html";  
$handle = fopen("$log_file", "w");
$htmlstarter = '<!doctype html><meta charset=utf-8><title>linkedinresttest logfile</title>';
$htmlstarter .= '<style type="text/css">'; 
$htmlstarter .= 'h3{';
$htmlstarter .= ' font:normal 30pt Arial;';
$htmlstarter .= ' color:#FFFFFF;';
$htmlstarter .= ' text-shadow: 0 1px 0 #ccc,';
$htmlstarter .= ' 0 2px 0 #c9c9c9,';
$htmlstarter .= ' 0 3px 0 #bbb,';
$htmlstarter .= ' 0 4px 0 #b9b9b9,';
$htmlstarter .= ' 0 5px 0 #aaa,';
$htmlstarter .= ' 0 6px 1px rgba(0,0,0,.1),';
$htmlstarter .= ' 0 0 5px rgba(0,0,0,.1),';
$htmlstarter .= ' 0 1px 3px rgba(0,0,0,.3),';
$htmlstarter .= ' 0 3px 5px rgba(0,0,0,.2),';
$htmlstarter .= ' 0 5px 10px rgba(0,0,0,.25),';
$htmlstarter .= ' 0 10px 10px rgba(0,0,0,.2),';
$htmlstarter .= ' 0 20px 20px rgba(0,0,0,.15);';
$htmlstarter .= '}';
$htmlstarter .= '#content .top{';
$htmlstarter .= 'margin:10px 10px 10px 10px;';
$htmlstarter .= 'padding:20px;';
$htmlstarter .= 'width:inherit;';
$htmlstarter .= 'height:inherit;';
$htmlstarter .= 'white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap;  word-wrap: break-word;';
$htmlstarter .= '-moz-box-shadow: 5px 5px 10px rgba(0,0,0,.8), inset 2px 2px 2px rgba(0,0,0,.2), inset -2px -2px 3px rgba(255,255,255,.85);';
$htmlstarter .= '-webkit-box-shadow: 5px 5px 10px rgba(0,0,0,.8), inset 2px 2px 2px rgba(0,0,0,.2), inset -2px -2px 3px rgba(255,255,255,.85);';
$htmlstarter .= 'box-shadow: 5px 5px 10px rgba(0,0,0,.8), inset 2px 2px 2px rgba(0,0,0,.2), inset -2px -2px 3px rgba(255,255,255,.85);';
$htmlstarter .= '-moz-border-radius: 5px;';
$htmlstarter .= 'border-radius: 5px;';
$htmlstarter .= 'background-color:rgba(224,224,224,.92);';
$htmlstarter .= '}';
$htmlstarter .= '</style>';
$htmlstarter .= '<div id="content">';
$htmlstarter .= '  <div class="top">';
fwrite($handle, $htmlstarter);

// Closes off the html of the log and exits
function myExit() {
    global $handle;
    fwrite($handle, '</div></div>');
    exit();
}

// Logs a line to the log
function logMsg($msg) {
    global $handle;
    fwrite($handle, '<p>' . $msg);  
}

// Logs an error to the log
function logMsgError($msg) {
    global $handle;
    fwrite($handle, '<h1 style="color:red;">' . $msg);  
}

// Logs a header to the log
function logMsgHead($msg) {
    global $handle;
    fwrite($handle, '<h3>' . $msg . '</h3>');  
}


// This is the standard urlencode function to use with oauth
function urlencode_oauth($str) {
  return
    str_replace('+',' ',str_replace('%7E','~',rawurlencode($str)));
}





// These are the linkedin oauth url endpoints
$links = array(
  'request_token'=>'https://api.linkedin.com/uas/oauth/requestToken',
  'authorize'=>'https://www.linkedin.com/uas/oauth/authorize',
  'access_token'=>'https://api.linkedin.com/uas/oauth/accessToken'
);


// This is the junction, taken when we redirect after we authorise
if (empty($_GET['oauth_token']) || empty($_GET['oauth_verifier']) || $_GET['oauth_token']!=$_SESSION['linkedin_oauth_token']) {
    // if we are in here we still have to get the request token and do the redirect
    $currentTime = strftime('%c');
    $currentURL = curPageURL();

    logMsg(  'We\'re doing the initial call to get the request token now.');
    logMsg(  'Timestamp: '. $currentTime);
    logMsg( 'Current page URL: ' . $currentURL);
    
    // 1 Set up the key first
    logMsgHead('1. Set up the key first, set the linkedin oath endpoint urls, and the oauth request parameters');
    logMsg( 'Create the API key here <a target=_blank href=https://www.linkedin.com/secure/developer>https://www.linkedin.com/secure/developer</a>');
    logMsg( 'Setting up the API key and Secret key...');

    logMsg( 'Consumer key: ' . LINKEDIN_KEY);
    logMsg( 'Secret key: ' . LINKEDIN_SECRET . '  !!!! NEVER GIVE ANYONE YOUR SECRET KEY !!!!');

    logMsg( 'Request token URL: ' . $links['request_token']);
    logMsg( 'Authorize URL: ' . $links['authorize']);
    logMsg( 'Access token URL: ' . $links['access_token']);


    // The user is redirected to this URL after they successfully authorize your application. 
    // This value is used only when the oauth_callback parameter in the requestToken call isn't provided
    $params = array(
      'oauth_callback'=>$currentURL,
      'oauth_consumer_key'=>LINKEDIN_KEY,
      'oauth_nonce'=>sha1(microtime()),
      'oauth_signature_method'=>'HMAC-SHA1',
      'oauth_timestamp'=>time(),
      'oauth_version'=>'1.0'
    );
    
    
    
    
    logMsgHead('2. Prepare the signature base string');
    logMsg('This is the single line string used for signing the request.');
    logMsg('In contains, POST, request URL, query string sorted by key (then value).');
    logMsg('These three items are url encoded and combined with & separator.');
    
    
    // sort parameters according to ascending order of key
    ksort($params); // !!! if 2 keys same we need to sub sort by values
    
    // prepare URL-encoded query string
    logMsg('There are the sorted oauth parameters:');
    $q = array();
    foreach ($params as $key=>$value) {
      logMsg( $key .'='. $value);
      $q[] = urlencode_oauth($key).'='.urlencode_oauth($value);
    }
    $q = implode('&',$q);
    
    // generate the base string for signature
    $parts = array(
      'POST',
      urlencode_oauth($links['request_token']),
      urlencode_oauth($q)
    );
    $base_string = implode('&',$parts);
    
    logMsg( 'base_string will be urlencoded and concatonated: ' . $parts[0] . ' and ' . $links['request_token'] . ' and ' . $q );
    logMsg( "This is the base_string: " . $base_string );
    
    
    logMsgHead('3. Get the signature');
    logMsg( 'The signature is calculated by passing the signature base string and signing key to the HMAC-SHA1 hashing algorithm' );
    logMsg( 'The output of the HMAC signing function is a binary string. This needs to be base64 encoded to produce the signature string.');
    logMsg( 'This signature is also generated by the server using the secret key and compared for equality to the signature you are sending');
    
    $key = urlencode_oauth(LINKEDIN_SECRET) . '&';
    $signature = base64_encode(hash_hmac('sha1',$base_string,$key,true));
    logMsg( 'This is the signature: ' . $signature );
    
    
    logMsgHead('4. Put the Signature into Parameters and Prepare Authorization Header');
    $params['oauth_signature'] = $signature;
    $str = array();
    foreach ($params as $key=>$value) {
      $str[] = $key . '="'.urlencode_oauth($value).'"';
    }
    $str = implode(', ',$str);
    $headers = array(
      'POST /uas/oauth/requestToken HTTP/1.1',
      'Host: api.linkedin.com',
      'Authorization: OAuth '.$str,
      'Content-Type: text/xml;charset=UTF-8',
      'Content-Length: 0',
      'Connection: close'
    );
    
    logMsgHead( '5. Send POST Request To LinkedIn');
    
    // Step Send Post request to Linkedin
    logMsg('Opening connection with LinkedIn');
    $fp = fsockopen("ssl://api.linkedin.com",443,$errno,$errstr,30);
    if (!$fp) { 
        logMsgError( 'Unable to connect to LinkedIn'); 
        myExit(); 
    }
    $out = implode("\r\n",$headers) . "\r\n\r\n";
    logMsg('Sending this to LinkedIn: ' . $out );
    fputs($fp,$out);
    
    // getting LinkedIn server response
    logMsgHead( '6. Process response from LinkedIn');
    logMsg('Reading from connection with LinkedIn');
    $res = '';
    $OAUTH_TOKEN_STR = 'oauth_token';
    $HTTP_STR = 'HTTP';
    $oauthpart = '';
    $httppart = '';
    while(($url_full_raw = fgets($fp,4096))!==false) {
        if (!strncmp($url_full_raw, $HTTP_STR, strlen($HTTP_STR))) {
            logMsg( 'Found the http response header: ' . $url_full_raw);
            $httppart = $url_full_raw; // save for later
            
            if (!strpos($httppart, '200 OK')) {
                logMsg('Error getting OAuth token and secret.'); 
                myExit();
            }
            else {
                logMsg('Oauth request ok so far.'); 
            }
        }
        elseif (!strncmp($url_full_raw, $OAUTH_TOKEN_STR, strlen($OAUTH_TOKEN_STR))) {
            logMsg( 'Found the oauth part: ' . $url_full_raw);
            $oauthpart = $url_full_raw; // save for later
        }
        else {
            logMsg( 'Line: ' . $url_full_raw );
        }
    }
    fclose($fp); // close connection to LinkedIn
    logMsg('Closed connection with LinkedIn');
    
    logMsgHead( '7. Process the oauth part of the response from LinkedIn');
    parse_str($oauthpart,$data);
    $oauth_token = $data['oauth_token'];
    $oauth_token_secret = $data['oauth_token_secret'];
    if (empty($oauth_token)) {
      logMsgError( 'We failed to get LinkedIn request token.'); 
      myExit();
    }
    else {
      logMsg( 'oauth token is: ' . $oauth_token );
      logMsg( 'oauth secret token is: ' . $oauth_token_secret );
    }
    
    logMsgHead( '8. We\'re storing the request tokens in session for now');
    
    // Step 10: store the response
    $_SESSION['linkedin_oauth_token'] = $oauth_token;
    $_SESSION['linkedin_oauth_token_secret'] = $oauth_token_secret;
    
    logMsg( '$_SESSION["linkedin_oauth_token"]='.$_SESSION["linkedin_oauth_token"] );
    logMsg( '$_SESSION["linkedin_oauth_token_secret"]='.$_SESSION["linkedin_oauth_token_secret"] );
    
    // Step 11
    logMsgHead( '9. We\'re redirecting user to accept page/linkedin login: '. $links['authorize'].'?oauth_token='.urlencode($oauth_token));
    header('Location: '.$links['authorize']. '?oauth_token='.urlencode($oauth_token));

}
else {
    if (empty($_GET['oauth_token']) || empty($_GET['oauth_verifier']) || $_GET['oauth_token']!=$_SESSION['linkedin_oauth_token']) {
      echo 'You must grant us access to proceed on.'; exit();
    }
    else {
      echo 'all good with the tokens so far<br>';
    }
    
    logMsgHead( 'we did it - now getting the access token!');
        
    $params = array(
      'oauth_consumer_key'=>LINKEDIN_KEY,
      'oauth_nonce'=>sha1(microtime()),
      'oauth_signature_method'=>'HMAC-SHA1',
      'oauth_timestamp'=>time(),
      'oauth_token'=>$_GET['oauth_token'],
      'oauth_verifier'=>$_GET['oauth_verifier'],
      'oauth_version'=>'1.0'
    );
        
    // sort parameters according to ascending order of key
    ksort($params);
    
    // prepare URL-encoded query string
    $q = array();
    foreach ($params as $key=>$value) {
      $q[] = urlencode_oauth($key).'='.urlencode_oauth($value);
    }
    $q = implode('&',$q);
    echo 'q = ' . $q . '<br>';
    
    
    // generate the base string for signature
    $parts = array(
      'POST',
      urlencode_oauth($links['access_token']),
      urlencode_oauth($q)
    );
    $base_string = implode('&',$parts);
        
    $key = urlencode_oauth(LINKEDIN_SECRET) . '&' . urlencode_oauth($_SESSION['linkedin_oauth_token_secret']);
    $signature = base64_encode(hash_hmac('sha1',$base_string,$key,true));    

    $params['oauth_signature'] = $signature;
    $str = array();
    foreach ($params as $key=>$value) {
      $str[] = $key . '="'.urlencode_oauth($value).'"';
    }
    $str = implode(', ',$str);
    $headers = array(
      'POST /uas/oauth/accessToken HTTP/1.1',
      'Host: api.linkedin.com',
      'Authorization: OAuth '.$str,
      'Content-Type: text/xml;charset=UTF-8',
      'Content-Length: 0',
      'Connection: close'
    );
    
    $fp = fsockopen("ssl://api.linkedin.com",443,$errno,$errstr,30);
    if (!$fp) { echo 'Unable to connect to LinkedIn'; exit(); }
    $out = implode("\r\n",$headers) . "\r\n\r\n";
    fputs($fp,$out);
    
    // getting LinkedIn server response
    $res = '';
    $OAUTH_TOKEN_STR = 'oauth_token';
    $HTTP_STR = 'HTTP';
    $oauthpart = '';
    $httppart = '';
    while(($url_full_raw = fgets($fp,4096))!==false) {
        if (!strncmp($url_full_raw, $HTTP_STR, strlen($HTTP_STR))) {
            logMsg( 'Found the http response header: ' . $url_full_raw);
            $httppart = $url_full_raw; // save for later
            
            if (!strpos($httppart, '200 OK')) {
                logMsg('Error getting access token and secret.'); 
                echo 'Failed to get LinkedIn access token.<br>';
                myExit();
            }
            else {
                logMsg('Oauth request ok so far.<br>'); 
                echo 'Oauth request ok so far.<br>';
            }
        }
        elseif (!strncmp($url_full_raw, $OAUTH_TOKEN_STR, strlen($OAUTH_TOKEN_STR))) {
            logMsg( 'Found the oauth part: ' . $url_full_raw.'<br>');
            $oauthpart = $url_full_raw; // save for later
            echo 'oauthpart is ' . $oauthpart . '<br>';
        }
        else {
            logMsg( 'Line: ' . $url_full_raw .'<br>');
        }
    }
    fclose($fp); // close connection to LinkedIn
    logMsg('Closed connection with LinkedIn');
    
    //logMsgHead( '7. Process the oauth part of the response from LinkedIn');
    parse_str($oauthpart,$data);
    $oauth_token = $data['oauth_token'];
    if (empty($oauth_token)) {
      logMsgError( 'We failed to get LinkedIn request token.'); 
      myExit();
    }
    else {
      logMsg( 'oauth token is: ' . $oauth_token );
    }

    $_SESSION['linkedin_access_token'] = $data['oauth_token'];
    $_SESSION['linkedin_access_token_secret'] = $data['oauth_token_secret'];
    
    echo "access token=" . $_SESSION['linkedin_access_token'].'<br>';
    echo "secret access token=" . $_SESSION['linkedin_access_token_secret'].'<br>';
    
    // unset the Request Token (not needed anymore)
    unset($_SESSION['linkedin_oauth_token']);
    unset($_SESSION['linkedin_oauth_token_secret']);

    echo 'we got the access token!<br><br> ';






    // Right now we have the access token, let's put it to good use by accessing the LinkedIn APIs
    $xml =
    '<?xml version="1.0" encoding="UTF-8"?>
    <share>
      <comment>I learn this from TheWebCafes</comment>
      <content>
         <title>Hello world!</title>
         <submitted-url>http://blog.thewebcafes.com</submitted-url>
         <submitted-image-url>http://blog.thewebcafes.com/img/example.jpg</submitted-image-url>
      </content>
      <visibility>
         <code>anyone</code>
      </visibility>
    </share>';
    $xml = ''; // we aren't doing share now...
    
    $oauth_timestamp = time();
    $params = array(
      'oauth_consumer_key'=>LINKEDIN_KEY,
      'oauth_nonce'=>'1234',//sha1(microtime()),
      'oauth_signature_method'=>'HMAC-SHA1',
      'oauth_timestamp'=>$oauth_timestamp,
      'oauth_token'=>$_SESSION['linkedin_access_token'],
      'oauth_version'=>'1.0'
    );
    
    // sort parameters according to ascending order of key
    ksort($params);
    
    // prepare URL-encoded query string
    $q = array();
    foreach ($params as $key=>$value) {
      $q[] = urlencode_oauth($key).'='.urlencode_oauth($value);
    }
    $q = implode('&',$q);
    echo 'q='.$q.'<br>';
    
    // generate the base string for signature
    $peopleURL = 'https://api.linkedin.com/v1/people/~';
    $parts = array(
      'GET',
      urlencode_oauth($peopleURL),
      urlencode_oauth($q)
    );
    $base_string = implode('&',$parts);    
    echo 'base string = ' . $base_string . '<br><br>';

    $key = urlencode_oauth(LINKEDIN_SECRET) . '&' . urlencode_oauth($_SESSION['linkedin_access_token_secret']);
    $signature = base64_encode(hash_hmac('sha1',$base_string,$key,true));

    $params['oauth_signature'] = $signature;
    $str = array();
    foreach ($params as $key=>$value) {
      $str[] = $key . '="'.urlencode_oauth($value).'"';
    }
    $str = implode(', ',$str);
    
    $headers = array(
      'GET /v1/people/~ HTTP/1.1',
      'Host: api.linkedin.com',
      'Authorization: OAuth '.$str,
      'Content-Type: text/xml;charset=UTF-8',
      'x-li-format: xml',
      'Content-Length: 0',//.strlen($xml),
      'Connection: close'
    );
    
    
    echo 'here are the headers <br>';
    echo 'LINKEDIN_KEY: '.LINKEDIN_KEY.'<br>';
    echo 'LINKEDIN_SECRET: '.LINKEDIN_SECRET.'<br>';
    echo "access token=" . $_SESSION['linkedin_access_token'].'<br>';
    echo "secret access token=" . $_SESSION['linkedin_access_token_secret'].'<br>';
    echo '$signature = ' . $signature.'<br>';
    echo 'base string = ' . $base_string . '<br>';

    
    echo $headers[0].'<br>';
    echo $headers[1].'<br>';
    echo $headers[2].'<br>';
    echo $headers[3].'<br>';
    echo $headers[4].'<br>';
    echo $headers[5].'<br>';
    
    echo '<br>Try this url<br>';
    echo $peopleURL . '?oauth_consumer_key='.LINKEDIN_KEY.'&oauth_nonce=1234&oauth_signature='.urlencode_oauth($signature).'&oauth_signature_method=HMAC-SHA1&oauth_timestamp='.$oauth_timestamp.'&oauth_token='.$_SESSION['linkedin_access_token'].'&oauth_version=1.0<br>';

    $fp = fsockopen("ssl://api.linkedin.com",443,$errno,$errstr,30);

    
    if (!$fp) { echo 'Unable to connect to LinkedIn'; exit(); }
    $out = implode("\r\n",$headers)."\r\n\r\n";//.$xml . "\r\n\r\n";
    fputs($fp,$out);
    
    echo 'REST call made to LinkedIn, getting response now<br>';
    
    // getting LinkedIn server response
    $res = '';
    $HTTP_STR = 'HTTP';
    $httppart = '';
    echo '<pre>';
    while(($url_full_raw = fgets($fp,4096))!==false) {
        echo 'response line: '. $url_full_raw . '<br>';
        if (!strncmp($url_full_raw, $HTTP_STR, strlen($HTTP_STR))) {
            logMsg( 'Found the http response header: ' . $url_full_raw);
            $httppart = $url_full_raw; // save for later
            
            if (!strpos($httppart, '200 OK')) {
                logMsg('Error getting access token and secret.'); 
                echo 'Failed to get correct response.<br>';
                myExit();
            }
            else {
                logMsg('request ok so far.<br>'); 
                echo 'request ok so far.<br>';
            }
        }
        else {
            logMsg( 'Line: ' . $url_full_raw .'<br>');
        }
    }
    fclose($fp); // close connection to LinkedIn
    echo '</pre>';    
    logMsg('Closed connection with LinkedIn');
    
}


myExit();
?>

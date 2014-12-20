<?php
/*
    Copyright by Hans Raaf (aka OderWat) http://oderwat.de/ && https://github.com/oderwat

    Losely based on work by Stéphane Depierrepont (aka Toorop) toorop@toorop.fr
    and by Vincent Giersch : https://github.com/gierschv

    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use this file except in compliance with the License. You may obtain a copy of
    the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations under
    the License.

 */

define('CACHEPATH',dirname(__FILE__).'/../cache');
define('CONFIGFILE',dirname(__FILE__).'/../config.php');

// this reads the clients (but only supports one with name hubic right now!)
$_prefix = '';
include(CONFIGFILE);

/*
function logfile($txt) {
	if(!is_string($txt)) {
		ob_start();
		print_r($txt);
		$txt=ob_get_contents();
		ob_end_clean();
	}
	$fh=fopen(CACHEPATH.'/swiftgateway.log','a');
	fputs($fh,$txt);
	fputs($fh,"\n");
	fclose($fh);
}
*/

function internal_error($txt){
	header("HTTP/1.0 500 Internal Server Error");
	nocache();
	if($txt) {
		print($txt);
	}
	die();
}

function nocache() {
	header("Expires: Mon, 1 Jan 2000 00:00:00 GMT");
	header("Last-Modified: ".gmdate("D, d M Y H:i:s")." GMT");
	header("Cache-Control: no-store, no-cache, must-revalidate");
	header("Cache-Control: post-check=0, pre-check=0",false);
	header("Pragma: no-cache");
}

function format_bytes($bytes, $precision = 2) {
	$units = array('B', 'KB', 'MB', 'GB', 'TB');

	$bytes = max($bytes, 0);
	$pow = floor(($bytes ? log($bytes) : 0) / log(1024));
	$pow = min($pow, count($units) - 1);

	// Uncomment one of the following alternatives
	// $bytes /= pow(1024, $pow);
	$bytes /= (1 << (10 * $pow));

	return round($bytes, $precision) . ' ' . $units[$pow];
}

// Curl is available ?
if(!function_exists('curl_init')) {
	internal_error('Curl seems to be not supported by your PHP version, checks : http://php.net/manual/en/curl.installation.php');
}

// Cache is ok ?
if(!file_exists(CACHEPATH)) {
	internal_error(CACHEPATH .' doesn\'t exists');
}
if(!is_writable(CACHEPATH)) {
	internal_error(CACHEPATH .' is not writable');
}

$port='';
if($_SERVER['SERVER_PORT']!=443 && $_SERVER['SERVER_PORT']!=80) {
	$port=":".$_SERVER['SERVER_PORT'];
} else {
	$port='';
}

$redirect_uri="https://".$_SERVER['SERVER_NAME'].$port.$_prefix."/callback/";

$client='hubic'; // fixed for now

$client_id=$clients[$client]['client_id'];
$client_secret=$clients[$client]['client_secret'];

$basic_auth=base64_encode($client_id.':'.$client_secret);

$cacheKey=md5($client);

$mode=false;

list($request)=explode('?',$_SERVER['REQUEST_URI']);
// Remove _prefix from url, if any
if ($_prefix!='') {
  if (!strncmp($_prefix, $request, strlen($_prefix))) {
    $request=substr($request, strlen($_prefix));
  }
}

switch($request) {
	case '/v1.0':
	case '/v1.0/':
	case '/auth':
	case '/auth/':
	case '/auth/v1.0':
	case '/auth/v1.0/':
		$mode='swift';
		break;

	case '/register':
	case '/register/':
		$mode='register';
		break;

	case '/usage':
	case '/usage/':
		$mode='usage';
		break;

	case '/':
		$mode='home';
		break;

	case '/callback':
	case '/callback/':
		$mode='callback';
		break;

	case '/success':
	case '/success/':
		$mode='success';
		break;

}

if($mode=='home') {
	header('HTTP/1.0 200 OK');
	nocache();
	print('<h3>Welcome to the Hubic to Switft Gateway!</h3><p>If you want to run your own HubiC To Swift Gateway you can fork the software at <a href="https://github.com/oderwat/hubic2swiftgate">GitHub</a>!</p><br><span style="font-size:10px">Software development and hosting sponsored by <a href="http://metatexx.de/">METATEXX GmbH</a></span>');
	die();
}

if(!$mode) {
	header('HTTP/1.0 404 Not Found');
	nocache();
	print("Not Found!");
	die();
}

if($mode=='swift') {
	// Get Auth from Headers to artificially limit access!
	if (!isset($_SERVER['HTTP_X_AUTH_USER']) || !isset($_SERVER['HTTP_X_AUTH_KEY'])) {
		header("HTTP/1.0 403 Forbidden");
		nocache();
		print('AUTH_USER and/or AUTH_KEY are missing!');
		die();
	} else {
		$auth_user = $_SERVER['HTTP_X_AUTH_USER'];
		$auth_key = $_SERVER['HTTP_X_AUTH_KEY'];
	}

	if($auth_user!=$client || $auth_key!=$clients[$client]['password']) {
		header('HTTP/1.0 403 Access Denied');
		nocache();
		print("ERROR : Access Denied");
		die();
	}
}

if($mode=='success') {
	header('HTTP/1.0 200 OK');
	nocache();
	print("Success: This Server is now registered with HubiC Filestorage!");
	die();
}

// User auf die Api Register Seite schicken
if($mode=='register') {
	if(!isset($_GET['client']) || $_GET['client']!=$client ||
		!isset($_GET['password']) || $_GET['password']!=$clients[$client]['password']) {
		header('HTTP/1.0 403 Access Denied');
		nocache();
		print("ERROR : Access Denied! Wrong Client or Password");
		die();
	}
	$uri='https://api.hubic.com/oauth/auth/?';
	$uri.='client_id='.$client_id;
	$uri.='&redirect_uri='.urlencode($redirect_uri);
	$uri.='&scope=usage.r,account.r,getAllLinks.r,credentials.r,activate.w,links.drw';
	$uri.='&response_type=code';
	$uri.='&state='.$client.':'.md5($clients[$client]['client_id']);
	header('HTTP/1.0 301 Redirect');
	nocache();
	header("Location: ".$uri);
	die();
}

$access_token=false;
$access_expires=0;
$refresh_token=false;

if($mode=='callback') {
	// we return from OAuth2 on HubiC Site
	if(!isset($_GET['code']) || !isset($_GET['state']) ||
		$_GET['state']!=$client.':'.md5($clients[$client]['client_id'])) {
		header('HTTP/1.0 412 Precondition failed');
		nocache();
		print("Illegal!");
		die();
	}
	$code=$_GET['code'];
	$uri.='&state='.$client.':'.md5($clients[$client]['client_id']);

	$c = curl_init('https://api.hubic.com/oauth/token/');
	curl_setopt($c, CURLOPT_HTTPHEADER, array(
		'Authorization: Basic '.$basic_auth
	));
	curl_setopt($c, CURLOPT_VERBOSE, 0);
	curl_setopt($c, CURLOPT_RETURNTRANSFER, true);

	curl_setopt($c, CURLOPT_POST, true );
	curl_setopt($c, CURLOPT_POSTFIELDS, array(
		'code' => $code,
		'redirect_uri' => $redirect_uri,
		'grant_type' => 'authorization_code'
	) );

	$r = curl_exec($c);
	$http_retcode = curl_getinfo($c, CURLINFO_HTTP_CODE);
	$error = curl_error($c);
	if ($http_retcode !== 200) {
		header('HTTP/1.0 200');
		nocache();
		print("HubiC api server responded with return code: ".$http_retcode);
		die();
	}

	$token = json_decode($r);

	if($token->token_type != 'Bearer') {
		internal_error('Unkknown Token Type: '.$token->token_type);
	}

	$access_token=$token->access_token;
	$access_expires=$token->expires_in+time();
	$refresh_token=$token->refresh_token;

	if (file_exists(CACHEPATH.'/'.$cacheKey)) {
		// delete outdated cached data
		unlink(CACHEPATH.'/'.$cacheKey);
	}

}

if (file_exists(CACHEPATH.'/'.$cacheKey)) {
	$cached=unserialize(file_get_contents(CACHEPATH.'/'.$cacheKey));
	if($mode=='swift' && $cached['os_expires']>time()) {
		// OS Token still valid
		header('X-Storage-Url: '.$cached['os_endpoint']);
		header('X-Auth-Token: '.$cached['os_token']);
		header('HTTP/1.0 204 No Content');
		//header('HTTP/1.0 200 OK');
		nocache();
		die();
	}

	// Preload hubic tokens from cache
	$access_token=$cached['access_token'];
	$access_expires=$cached['access_expires'];
	$refresh_token=$cached['refresh_token'];

}

if(!$access_token || $access_expires<time()) {
	$c = curl_init('https://api.hubic.com/oauth/token/');
	curl_setopt($c, CURLOPT_HTTPHEADER, array(
		'Authorization: Basic '.$basic_auth
	));

	curl_setopt($c, CURLOPT_VERBOSE, 0);
	curl_setopt($c, CURLOPT_RETURNTRANSFER, true);

	curl_setopt($c, CURLOPT_POST, true );
	curl_setopt($c, CURLOPT_POSTFIELDS, array(
		'refresh_token' => $refresh_token,
		'grant_type' => 'refresh_token'
	) );

	$r = curl_exec($c);
	$http_retcode = curl_getinfo($c, CURLINFO_HTTP_CODE);
	$error = curl_error($c);
	if ($http_retcode !== 200) {
		header('HTTP/1.0 ' . $http_retcode);
		nocache();
		print("ERROR 178: ".$error);
		die();
	}

	$token = json_decode($r);

	if($token->token_type != 'Bearer') {
		internal_error('Unkknown Token Type: '.$token->token_type);
	}

	$access_token=$token->access_token;
}

if($mode=='usage') {
	$c = curl_init('https://api.hubic.com/1.0/account/usage/');
	curl_setopt($c, CURLOPT_HTTPHEADER, array(
		'Authorization: Bearer '.$access_token
	));

	curl_setopt($c, CURLOPT_VERBOSE, 0);
	curl_setopt($c, CURLOPT_RETURNTRANSFER, true);

	$r = curl_exec($c);
	$http_retcode = curl_getinfo($c, CURLINFO_HTTP_CODE);
	$error = curl_error($c);
	if ($http_retcode !== 200) {
		header('HTTP/1.0 ' . $http_retcode);
		nocache();
		print("ERROR 207 : ".$error);
		print_r('access token: '.$access_token);
		flush();
		die();
	}

	$usage = json_decode($r);

	print('<pre>Usage: ');
	print(format_bytes($usage->used).' / '.format_bytes($usage->quota));
	die();
}

// Nun OpenStack Swift Storage Token holen
$c = curl_init('https://api.hubic.com/1.0/account/credentials');
curl_setopt($c, CURLOPT_HTTPHEADER, array(
	'Authorization: Bearer '.$access_token
));

curl_setopt($c, CURLOPT_VERBOSE, 0);
curl_setopt($c, CURLOPT_RETURNTRANSFER, true);

$r = curl_exec($c);
$http_retcode = curl_getinfo($c, CURLINFO_HTTP_CODE);
$error = curl_error($c);
if ($http_retcode !== 200) {
	header('HTTP/1.0 ' . $http_retcode);
	nocache();
	print("ERROR 207 : ".$error);
	die();
}

$storage = json_decode($r);

// put in cache
file_put_contents(CACHEPATH.'/'.$cacheKey,serialize(
	array(
		'os_expires'=>strtotime($storage->expires),
		'os_endpoint'=>$storage->endpoint,
		'os_token'=>$storage->token,
		'access_token'=>$access_token,
		'access_expires'=>$access_expires,
		'refresh_token'=>$refresh_token
	)));

if($mode=='callback') {
	header('HTTP/1.0 301 Redirect');
	nocache();
	header('Location: https://'.$_SERVER['HTTP_HOST'].$_prefix.'/success/');
} else if($mode=='swift') {
	header('X-Storage-Url: '.$storage->endpoint);
	header('X-Auth-Token: '.$storage->token);
	header('HTTP/1.0 204 No Content');
//	header('HTTP/1.0 200 OK'); // dulwich swift-repo does not understand 204
	nocache();
} else {
	header('HTTP/1.0 404 Not Found');
	nocache();
	print("Not Found!");
}

<?php
/*
 * PHP Mcrypt AES 加密 与 OpenSSL 加密通用
 */

/*
 * 补齐需要加密的字符串
 */
function add_padding($string, $blocksize = 16) {
	$len = strlen ( $string );
	$pad = $blocksize - ($len % $blocksize);
	$string .= str_repeat ( chr ( $pad ), $pad );
	return $string;
}

/*
 * 使用 Null char（0x00） 补齐密钥
 */
function add_padding_key($string, $blocksize = 16) {
	$len = strlen ( $string );

	if($len >= $blocksize)
		return $string;

	$pad = $blocksize - $len;
	$string .= str_repeat ( chr ( 0 ), $pad );
	return $string;
}

/*
 * 由于明文是经过字符补齐后，再进行的加密。所以，解密后，需要移除补齐字符
 */
function strippadding($string)
{
	$slast = ord(substr($string, -1));
	$slastc = chr($slast);
	$pcheck = substr($string, -$slast);
	if(preg_match("/$slastc{".$slast."}/", $string)){
		$string = substr($string, 0, strlen($string)-$slast);
		return $string;
	} else {
		return false;
	}
}

/*
 * 加密字符串尾部有补齐的字符，一定要保留，不然无法解密
 */
function encrypt_aes_256_cbc($key, $iv, $plaintext) {
	// 标准 AES-256-CBC 的 IV 长度是16，而 MCRYPT_RIJNDAEL_256 的 IV 长度是 32。
	// 使用 MCRYPT_RIJNDAEL_128 初始化，得到 IV 长度 16。
	$cipher = mcrypt_module_open ( MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '' );
	
	// 初始化加密句
	// key 长度 16 时，mcrypt_generic() 会使用 MCRYPT_RIJNDAEL_128 生成结果
	// key 长度 32 时，mcrypt_generic() 会使用 MCRYPT_RIJNDAEL_256 生成结果
	if (mcrypt_generic_init ( $cipher, add_padding_key( $key, 32 ), add_padding_key($iv, 16)) != - 1) {
		
		// 加密数据
		$ciphertext = mcrypt_generic ( $cipher, add_padding ( $plaintext ) );
		
		mcrypt_generic_deinit ( $cipher );
		mcrypt_module_close ( $cipher );
		
		return base64_encode($ciphertext);
	}
	
	return "";
}

function decrypt_aes_256_cbc($key, $iv, $ciphertext) {
	$cipher = mcrypt_module_open ( MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '' );
	
	// 初始化加密句柄
	if (mcrypt_generic_init ( $cipher, add_padding_key( $key, 32 ), add_padding_key($iv, 16)) != - 1) {
	
		// 加密数据
		$plaintext = mdecrypt_generic ( $cipher, base64_decode($ciphertext));
		
		mcrypt_generic_deinit ( $cipher );
		mcrypt_module_close ( $cipher );
	
		return strippadding($plaintext);
	}
	
	return "";
}

function print_result($title, $raw_text, $ciphertext, $plaintext) {
	echo  PHP_EOL .  "##### " . $title . " #####" . PHP_EOL;
	echo "    原始文本：" . $raw_text . PHP_EOL;
	echo "加密后的文本：" . $ciphertext . PHP_EOL;
	echo "解密后的文本：" . $plaintext . PHP_EOL;
}

$raw_text = "Hello, World!";
$key = '0123456789:;<=>?';
$iv = '0123456789:;<=>?';

##### PHP Mcrypt #####
$php_ciphertext = encrypt_aes_256_cbc ( $key, $iv, $raw_text );

$php_plaintext = decrypt_aes_256_cbc ( $key, $iv, $php_ciphertext );

print_result("PHP Mcrypt", $raw_text, $php_ciphertext, $php_plaintext);

##### OpenSSL #####
$openssl_cmd = 
	"openssl enc -aes-256-cbc -K ".bin2hex($key)." -iv ".bin2hex($iv) . " -a";

$openssl_ciphertext = 
	exec("echo -n \"" . $raw_text . "\"|" . $openssl_cmd);

$openssl_plaintext = 
	exec (
		"echo \"" . $openssl_ciphertext . "\"|" . $openssl_cmd . " -d");

print_result("OpenSSL", $raw_text, $openssl_ciphertext, $openssl_plaintext);


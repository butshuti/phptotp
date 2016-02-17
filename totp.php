<?php
class TOTP{	
  	//Charset as defined by RFC3548
	private $charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
  	//Window for clock differences (x30 seconds) , +/- $skewx30sec
  	private $skew = 2;
    /**
    *base32encodestr
    *
    *converts ascii string into base32
    *@param string $str The ascii input string
    *@return string a base32 version of the input string
    */
    public function base32encodestr($str){
        if(empty($str))return "";
        $len = strlen($str);
        $nquanta = ceil($len/5);//1 character is 8 bits, and a quantum is 40 bits
        $leftover = $len % 5;
        /*
        If last quantum has less than 40 bits (5 chars),
        add bits with 0 value to the right.
        */
        if($leftover > 0){
            for($i=0; $i<5-$leftover;$i++){
                $str .= "\0";
            }
        }
        $_8bitchars = "";
        $encoded = "";
        $quanta = str_split($str, 5);
        foreach($quanta as $quantum){
            for($i=0; $i<strlen($quantum); $i++){
                $_8bitchars .= str_pad(decbin(ord($quantum[$i])), 8, "0", STR_PAD_LEFT);
            }
        }
        foreach(str_split($_8bitchars, 5) as $_5bitchar)
        {
            $encoded .= $this->charset[bindec($_5bitchar)];
        }

        if($leftover == 1){
            $encoded = substr_replace($encoded, "======", strlen($encoded)-6);
        }elseif($leftover == 2){
            $encoded = substr_replace($encoded, "====", strlen($encoded)-4);
        }
        elseif($leftover == 3){
            $encoded = substr_replace($encoded, "===", strlen($encoded)-3);
        }
        elseif($leftover == 4){
            $encoded = substr_replace($encoded, "=", strlen($encoded)-1);
        }
        return $encoded;
    }

    /*
          Reverse base32encode 
          */
    public function strdecodebase32($str){
      if(strlen($str) % 8 > 0){
        throw new Exception("Str length must be a multiple of 8");
      }
      if(empty($str))return "";
      $len = strpos($str, "=");
      if($len !== FALSE){
        $str = substr($str, 0, $len);
      }
      $quanta = str_split($str, 8);
      $decoded = "";
      foreach($quanta as $quantum){
        $_8bitchars = "";
        for($i=0; $i<strlen($quantum); $i++){
          $code = strpos($this->charset, $quantum[$i]);
          if($code === FALSE){
            throw new Exception("Invalid charset.");
          }
          $_8bitchars .= str_pad(decbin($code), 5, "0", STR_PAD_LEFT);
        }
        foreach(str_split($_8bitchars,8) as $char){
          $decoded .= chr(bindec($char));
        }
      }
      return $decoded;
    }

    private function int_to_bytestring($num, $padding=8){
      /*
       Turns an integer into the OATH specified
       bytestring
       */
      $ret = array();
      $idx=0;
      while($num != 0){
        $ret[$idx++] = chr($num & 0xff);
        $num = $num >> 8;
      }
      while($idx < $padding){
        $ret[$idx++] = chr(0x00);
      }
      return implode("", array_reverse($ret));
    }

  public function generate_truncated_otp($secret, $counter, $length=6){
      //Timecode derived from counter
      $key = $this->int_to_bytestring($counter);
      //Compute a 20-byte HMAC from the secret and timecode:
      $LEN = 20;
      $sharedKey = $this->strdecodebase32($secret);
      $hash = hash_hmac("sha1", $key, $sharedKey);
      /*
      Convert hex-encoded string to dec-encoded byte array
      */
      foreach(str_split($hash,2) as $hex)
      {
          $hmac[]=hexdec($hex);
      }
      //Put selected bytes into result int to produce the OTP
      //Algorithm from RFC 6238
      $offs = $hmac[$LEN-1] & 0xf;
      $ret = (($hmac[$offs] & 0x7f) << 24) |
          (($hmac[$offs+1] & 0xff) << 16) |
          (($hmac[$offs+2] & 0xff) << 8) |
          ($hmac[$offs+3] & 0xff);
      $ret %= pow(10, $length);
      return str_pad($ret, $length, "0", STR_PAD_LEFT);
  }

  private function cur_timecode($interval=30){
      $t = time();
      return intval($t/$interval);
  }
  
  public function get_current_otps($secret){
  	$ret = array();
    $start = $this->cur_timecode();
    for($i=-($this->skew); $i<=$this->skew; $i++)
    {
      $checktime = (int)($start+$i);
	  $ret[] = $this->generate_truncated_otp($secret, $checktime);
    }
    return $ret;
  }
  
  public function validate_code($secret, $code){
  	$start = $this->cur_timecode();
    for($i=-($this->skew); $i<=$this->skew; $i++)
    {
      $checktime = (int)($start+$i);
	  $tok = intval($this->generate_truncated_otp($secret, $checktime));
      if (intval($code) == $tok)
      {
        return true;
      }
    }
    return false;
  }
}

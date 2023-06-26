#!/usr/bin/env php
<?

/*
Copyright (c) 2009-2010 Open Information Security Foundation
Copyright (c) 2010-2013 Qualys, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

- Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

- Neither the name of the Qualys, Inc. nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


/*

ZLIB Compressed Data Format Specification version 3.3
http://www.ietf.org/rfc/rfc1950.txt

DEFLATE Compressed Data Format Specification version 1.3
http://www.ietf.org/rfc/rfc1951.txt

GZIP file format specification version 4.3
http://www.ietf.org/rfc/rfc1952.txt

*/

class GzipTest {

  private $compressionMethod = 0x08;

  private $forcedFlags = false;

  private $filename = false;
  
  private $comment = false;
  
  private $extra = false;
  
  private $textFlag = false;
  
  private $useHeaderCrc = false;
  
  private $headerCrc = false;
  
  private $crc32 = false;
  
  private $isize = false;
  
  private $data = "The five boxing wizards jump quickly.";
  
  private $xfl = 0;
  
  public function setCompressionMethod($m) {
    $this->compressionMethod = $m;
  }
  
  public function setCrc32($crc) {
    $this->crc32 = $crc;
  }
  
  public function setInputSize($len) {
    $this->isize = $len;
  }
  
  public function setXfl($xfl) {
    $this->xfl = $xfl;
  }
  
  public function setFilename($filename) {
    $this->filename = $filename;
  }
  
  public function setComment($comment) {
    $this->comment = $comment;
  }
  
  public function setExtra($extra) {
    $this->extra = $extra;
  }
  
  public function setTextFlag($b) {
    $this->textFlag = $b;
  }
  
  public function useHeaderCrc($b) {
    $this->useHeaderCrc = $b;
  }
  
  public function setHeaderCrc($crc) {
    $this->headerCrc = $crc;
  }
  
  public function setFlags($f) {
    $this->forcedFlags = $f;
  }
  
  public function getFlags() {
    if ($this->forcedFlags !== false) {
      return $this->forcedFlags;
    }
    
    $flags = 0;
    
    // FTEXT
    if ($this->textFlag) {
      $flags = $flags | 0x01;
    }
    
    // FHCRC
    if ($this->useHeaderCrc) {
      $flags = $flags | 0x02;
    }
    
    // FEXTRA
    if ($this->extra !== false) {
      $flags = $flags | 0x04;
    }
    
    // FNAME
    if ($this->filename !== false) {
      $flags = $flags | 0x08;
    }
    
    // FCOMMENT
    if ($this->comment !== false) {
      $flags = $flags | 0x16;
    }
    
    return $flags;
  }
  
  public function setData($data) {
    $this->data = $data;
  }
  
  public function writeTo($filename) {
    $fp = fopen($filename, "w+");
    $this->write($fp);
    fclose($fp);
  }

  public function write($fp) {
    $header = "";
    
    // header (ID1 + ID2)
    $header .= "\x1f\x8b";
    
    // compression method (CM)
    $header .= pack("C", $this->compressionMethod);
    
    // flags (FLG)
    $header .= pack("C", $this->getFlags());
    
    // mtime (MTIME)
    $header .= "\x9c\x54\xf4\x50";
    
    // extra flags (XFL)
    $header .= pack("C", $this->xfl);
    
    // operating system (OS)
    $header .= "\xff";
    
    // FEXTRA
    if ($this->extra !== false) {
      $header .= pack("v", strlen($this->extra));
      $header .= $this->extra;
    }
    
    // FNAME
    if ($this->filename !== false) {
      $header .= $this->filename;
      $header .= "\x00";
    }
    
    // FCOMMENT
    if ($this->comment !== false) {
      $header .= $this->comment;
      $header .= "\x00";
    }
    
    fwrite($fp, $header);
    
    // FHCRC
    if ($this->useHeaderCrc) {
      if ($this->headerCrc !== false) {
        // "The CRC16 consists of the two least significant bytes of the CRC32 [...]"
        fwrite($fp, pack("v", crc32($header)));
      } else {
        fwrite($fp, pack("v", $this->headerCrc));
      }
    }
    
    // compressed blocks
    $compressedData = gzcompress($this->data);
    // The gzcompress() function does not produce output that's fully compatible with gzip,
    // so we need to strip out the extra data: remove 2 bytes from the beginning
    // (CMF and FLG) and 4 bytes from the end (Adler CRC).
    $compressedData = substr($compressedData, 2, strlen($compressedData) - 6);
    fwrite($fp, $compressedData);
    
    // CRC32
    if ($this->crc32 === false) {
      fwrite($fp, pack("V", crc32($this->data)));
    } else {
      fwrite($fp, pack("V", $this->crc32));
    }
    
    // uncompressed size (ISIZE)
    if ($this->isize === false) {
      fwrite($fp, pack("V", strlen($this->data)));
    } else {
      fwrite($fp, pack("V", $this->isize));
    }
  }
}

// 01: minimal file
$gz = new GzipTest();
$gz->writeTo("gztest-01-minimal.gz");

// 02: with FNAME
$gz = new GzipTest();
$gz->setFilename("file.txt");
$gz->writeTo("gztest-02-fname.gz");

// 03: with FCOMMENT
$gz = new GzipTest();
$gz->setComment("COMMENT");
$gz->writeTo("gztest-03-fcomment.gz");

// 04: with FHCRC
$gz = new GzipTest();
$gz->useHeaderCrc(true);
$gz->writeTo("gztest-04-fhcrc.gz");

// 05: with FEXTRA
$gz = new GzipTest();
$gz->setExtra("EXTRA");
$gz->writeTo("gztest-05-fextra.gz");

// 06: with FTEXT
$gz = new GzipTest();
$gz->setTextFlag(true);
$gz->writeTo("gztest-06-ftext.gz");

// 07: with FRESERVED1
$gz = new GzipTest();
$gz->setFlags($gz->getFlags() | 0x20);
$gz->writeTo("gztest-07-freserved1.gz");

// 08: with FRESERVED2
$gz = new GzipTest();
$gz->setFlags($gz->getFlags() | 0x40);
$gz->writeTo("gztest-08-freserved2.gz");

// 09: with FRESERVED3
$gz = new GzipTest();
$gz->setFlags($gz->getFlags() | 0x80);
$gz->writeTo("gztest-09-freserved3.gz");

// 10: Two parts (compressed streams) 
$gz = new GzipTest();
$fp = fopen("gztest-10-multipart.gz", "w+");
$gz->setFilename("file1.txt");
$gz->write($fp);
$gz->setData("The quick brown fox jumps over the lazy dog.");
$gz->setFilename("file2.txt");
$gz->write($fp);
fclose($fp);

// 11: Invalid compression method
$gz = new GzipTest();
$gz->setCompressionMethod(0x07);
$gz->writeTo("gztest-11-invalid-method.gz");

// 12: Invalid CRC32
$gz = new GzipTest();
$gz->setCrc32(0xffffffff);
$gz->writeTo("gztest-12-invalid-crc32.gz");

// 13: Invalid ISIZE
$gz = new GzipTest();
$gz->setData("Grumpy Wizards make toxic brew for the Evil Queen and Jack.");
$gz->setInputSize(0x10);
$gz->writeTo("gztest-13-invalid-isize.gz");

// 14: Invalid extra flags (XFL)
$gz = new GzipTest();
$gz->setXfl(0xff);
$gz->writeTo("gztest-14-invalid-xfl.gz");

// 15: Invalid header CRC (FHCRC)
$gz = new GzipTest();
$gz->useHeaderCrc(true);
$gz->setHeaderCrc(0xffff);
$gz->writeTo("gztest-15-invalid-fhcrc.gz");

?>

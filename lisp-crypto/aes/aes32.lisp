;;;; AES encryption in ANSI Common Lisp
;;;  
;;;; Licence: LGPL
;;;
;;;; Copyright: Joern Inge Vestgaarden, 2005
;;;             <jivestgarden at gmail.com>
;;;
;;;; $Id: aes32.lisp,v 1.8 2007/01/28 10:40:23 jornv Exp $
;;;
;;;; AES (Advanced Encryption Standard - Rijndael) is a FIPS approved
;;;    block chipher (FIPS 197) designed by Joan Daemen and Vincent Rijmen.
;;;    Key lengths are 128, 192, 256 bits - block length is 128 bits.
;;;
;;;; Documentation
;;;    - FIPS-197, Nov. 26, 2001
;;;    - AES Proposal: Rijndal, by Joan Daemen and Vincent Rijmen
;;;    - Christophe Devine's (beautiful) C-implementation
;;;
;;;; Implementation
;;;    Based on Christophe Devine's C-implementation.
;;;    Encryption with CMUCL/SBCL is about 2-3 times 
;;;    slower than the C version.
;;;
;;; 
;;;; TODO
;;;    - make make system (including packages) 
;;:    - testing (for me)
;;:    - testing (for somebody else)
;;:    - obtain speed for other CL implementations than CMUCL/SBCL 
;;;      (for somebody else)
;;:    - optimise key expansion (no priority)
;;:    - testing
;;:    - wash the dishes (for me)
;;;    - make standardised interface (for somebody else)
;;:
;;;; About optimisation
;;;    This implementation is pure ANSI CL but optimisation 
;;;    is tailored for CMUCL/SBCL
;;;    It exploits ability to fast 32 bits arithmetic and also
;;;    the ability to automatically fixnum expressions of the kind
;;;    (declare (type (unsigned-byte 28) i) (+ i 1))
;;;    Thus, no typecasts are necessary in the program.
;;;    The whole encryption is unrolled which seems to speed 
;;;    up with a factor of 2.
;;;    


(in-package :aes32)

(defmacro define-constant (name value &optional doc)
  "Works as defconstant. Made to avoid trouble with sbcl's strict
interpretation of the ansi standard."
  (let ((old-value (gensym)))
    `(defconstant ,name 
      (if (boundp ',name) 
	  (let ((,old-value (symbol-value ',name)))
	     (if (equalp ,old-value ,value)
		 ,old-value
		 ,value))
	  ,value)
      ,@(when doc (list doc)))))

(declaim (inline sub-word rot-byte-L pack-bytes get-byte))

(defstruct aes-key
  "The AES key"  
  ;; In order to make the structure of encryption and decryption
  ;; similar, the forward and reverse keys are sligthly different
  ;; (referred to as equivalent inverse chiper in the documentation).
  ;; The difference is an extra invMixColumns in the inverse cipher.
  (rounds 0 :type fixnum)  ;; number of rounds (function of key length)
  (bits 0   :type fixnum)  ;; number of bits, 128, 192, or 256
  (fkey nil)               ;; forward key
  (rkey nil))              ;; reverse key
  
(define-constant +aes-block-bits+ '(128) "All allowed block lengths")
(define-constant +aes-key-bits+ '(128 192 256) "All allowed key lengths")

(defmacro rot-byte-R ()
  "Byte roation to the right"
  ;; This is a macro since it is called when making constants
  (let ((word (gensym)))
    `(lambda (,word) 
      (logxor (ash (ldb (byte 8 0) ,word) 24)
       (ash ,word -8)))))

(define-constant +fs+
    (make-array
     256 :element-type '(unsigned-byte 8)
     :initial-contents
     '(#X63 #X7C #X77 #X7B #XF2 #X6B #X6F #XC5 
       #X30 #X01 #X67 #X2B #XFE #XD7 #XAB #X76 
       #XCA #X82 #XC9 #X7D #XFA #X59 #X47 #XF0 
       #XAD #XD4 #XA2 #XAF #X9C #XA4 #X72 #XC0 
       #XB7 #XFD #X93 #X26 #X36 #X3F #XF7 #XCC 
       #X34 #XA5 #XE5 #XF1 #X71 #XD8 #X31 #X15 
       #X04 #XC7 #X23 #XC3 #X18 #X96 #X05 #X9A 
       #X07 #X12 #X80 #XE2 #XEB #X27 #XB2 #X75 
       #X09 #X83 #X2C #X1A #X1B #X6E #X5A #XA0 
       #X52 #X3B #XD6 #XB3 #X29 #XE3 #X2F #X84 
       #X53 #XD1 #X00 #XED #X20 #XFC #XB1 #X5B 
       #X6A #XCB #XBE #X39 #X4A #X4C #X58 #XCF 
       #XD0 #XEF #XAA #XFB #X43 #X4D #X33 #X85 
       #X45 #XF9 #X02 #X7F #X50 #X3C #X9F #XA8 
       #X51 #XA3 #X40 #X8F #X92 #X9D #X38 #XF5 
       #XBC #XB6 #XDA #X21 #X10 #XFF #XF3 #XD2 
       #XCD #X0C #X13 #XEC #X5F #X97 #X44 #X17 
       #XC4 #XA7 #X7E #X3D #X64 #X5D #X19 #X73 
       #X60 #X81 #X4F #XDC #X22 #X2A #X90 #X88 
       #X46 #XEE #XB8 #X14 #XDE #X5E #X0B #XDB 
       #XE0 #X32 #X3A #X0A #X49 #X06 #X24 #X5C 
       #XC2 #XD3 #XAC #X62 #X91 #X95 #XE4 #X79 
       #XE7 #XC8 #X37 #X6D #X8D #XD5 #X4E #XA9 
       #X6C #X56 #XF4 #XEA #X65 #X7A #XAE #X08 
       #XBA #X78 #X25 #X2E #X1C #XA6 #XB4 #XC6 
       #XE8 #XDD #X74 #X1F #X4B #XBD #X8B #X8A 
       #X70 #X3E #XB5 #X66 #X48 #X03 #XF6 #X0E 
       #X61 #X35 #X57 #XB9 #X86 #XC1 #X1D #X9E 
       #XE1 #XF8 #X98 #X11 #X69 #XD9 #X8E #X94 
       #X9B #X1E #X87 #XE9 #XCE #X55 #X28 #XDF 
       #X8C #XA1 #X89 #X0D #XBF #XE6 #X42 #X68 
       #X41 #X99 #X2D #X0F #XB0 #X54 #XBB #X16 )))

(define-constant +rs+
    (make-array
     256 :element-type '(unsigned-byte 8)
     :initial-contents
     '(#X52 #X09 #X6A #XD5 #X30 #X36 #XA5 #X38 
       #XBF #X40 #XA3 #X9E #X81 #XF3 #XD7 #XFB 
       #X7C #XE3 #X39 #X82 #X9B #X2F #XFF #X87 
       #X34 #X8E #X43 #X44 #XC4 #XDE #XE9 #XCB 
       #X54 #X7B #X94 #X32 #XA6 #XC2 #X23 #X3D 
       #XEE #X4C #X95 #X0B #X42 #XFA #XC3 #X4E 
       #X08 #X2E #XA1 #X66 #X28 #XD9 #X24 #XB2 
       #X76 #X5B #XA2 #X49 #X6D #X8B #XD1 #X25 
       #X72 #XF8 #XF6 #X64 #X86 #X68 #X98 #X16 
       #XD4 #XA4 #X5C #XCC #X5D #X65 #XB6 #X92 
       #X6C #X70 #X48 #X50 #XFD #XED #XB9 #XDA 
       #X5E #X15 #X46 #X57 #XA7 #X8D #X9D #X84 
       #X90 #XD8 #XAB #X00 #X8C #XBC #XD3 #X0A 
       #XF7 #XE4 #X58 #X05 #XB8 #XB3 #X45 #X06 
       #XD0 #X2C #X1E #X8F #XCA #X3F #X0F #X02 
       #XC1 #XAF #XBD #X03 #X01 #X13 #X8A #X6B 
       #X3A #X91 #X11 #X41 #X4F #X67 #XDC #XEA 
       #X97 #XF2 #XCF #XCE #XF0 #XB4 #XE6 #X73 
       #X96 #XAC #X74 #X22 #XE7 #XAD #X35 #X85 
       #XE2 #XF9 #X37 #XE8 #X1C #X75 #XDF #X6E 
       #X47 #XF1 #X1A #X71 #X1D #X29 #XC5 #X89 
       #X6F #XB7 #X62 #X0E #XAA #X18 #XBE #X1B 
       #XFC #X56 #X3E #X4B #XC6 #XD2 #X79 #X20 
       #X9A #XDB #XC0 #XFE #X78 #XCD #X5A #XF4 
       #X1F #XDD #XA8 #X33 #X88 #X07 #XC7 #X31 
       #XB1 #X12 #X10 #X59 #X27 #X80 #XEC #X5F 
       #X60 #X51 #X7F #XA9 #X19 #XB5 #X4A #X0D 
       #X2D #XE5 #X7A #X9F #X93 #XC9 #X9C #XEF 
       #XA0 #XE0 #X3B #X4D #XAE #X2A #XF5 #XB0 
       #XC8 #XEB #XBB #X3C #X83 #X53 #X99 #X61 
       #X17 #X2B #X04 #X7E #XBA #X77 #XD6 #X26 
       #XE1 #X69 #X14 #X63 #X55 #X21 #X0C #X7D )))
  
(define-constant +ft0+
    (make-array
     256 :element-type '(unsigned-byte 32)
     :initial-contents
     '(#XC66363A5 #XF87C7C84 #XEE777799 #XF67B7B8D 
       #XFFF2F20D #XD66B6BBD #XDE6F6FB1 #X91C5C554 
       #X60303050 #X02010103 #XCE6767A9 #X562B2B7D 
       #XE7FEFE19 #XB5D7D762 #X4DABABE6 #XEC76769A 
       #X8FCACA45 #X1F82829D #X89C9C940 #XFA7D7D87 
       #XEFFAFA15 #XB25959EB #X8E4747C9 #XFBF0F00B 
       #X41ADADEC #XB3D4D467 #X5FA2A2FD #X45AFAFEA 
       #X239C9CBF #X53A4A4F7 #XE4727296 #X9BC0C05B 
       #X75B7B7C2 #XE1FDFD1C #X3D9393AE #X4C26266A 
       #X6C36365A #X7E3F3F41 #XF5F7F702 #X83CCCC4F 
       #X6834345C #X51A5A5F4 #XD1E5E534 #XF9F1F108 
       #XE2717193 #XABD8D873 #X62313153 #X2A15153F 
       #X0804040C #X95C7C752 #X46232365 #X9DC3C35E 
       #X30181828 #X379696A1 #X0A05050F #X2F9A9AB5 
       #X0E070709 #X24121236 #X1B80809B #XDFE2E23D 
       #XCDEBEB26 #X4E272769 #X7FB2B2CD #XEA75759F 
       #X1209091B #X1D83839E #X582C2C74 #X341A1A2E 
       #X361B1B2D #XDC6E6EB2 #XB45A5AEE #X5BA0A0FB 
       #XA45252F6 #X763B3B4D #XB7D6D661 #X7DB3B3CE 
       #X5229297B #XDDE3E33E #X5E2F2F71 #X13848497 
       #XA65353F5 #XB9D1D168 #X00000000 #XC1EDED2C 
       #X40202060 #XE3FCFC1F #X79B1B1C8 #XB65B5BED 
       #XD46A6ABE #X8DCBCB46 #X67BEBED9 #X7239394B 
       #X944A4ADE #X984C4CD4 #XB05858E8 #X85CFCF4A 
       #XBBD0D06B #XC5EFEF2A #X4FAAAAE5 #XEDFBFB16 
       #X864343C5 #X9A4D4DD7 #X66333355 #X11858594 
       #X8A4545CF #XE9F9F910 #X04020206 #XFE7F7F81 
       #XA05050F0 #X783C3C44 #X259F9FBA #X4BA8A8E3 
       #XA25151F3 #X5DA3A3FE #X804040C0 #X058F8F8A 
       #X3F9292AD #X219D9DBC #X70383848 #XF1F5F504 
       #X63BCBCDF #X77B6B6C1 #XAFDADA75 #X42212163 
       #X20101030 #XE5FFFF1A #XFDF3F30E #XBFD2D26D 
       #X81CDCD4C #X180C0C14 #X26131335 #XC3ECEC2F 
       #XBE5F5FE1 #X359797A2 #X884444CC #X2E171739 
       #X93C4C457 #X55A7A7F2 #XFC7E7E82 #X7A3D3D47 
       #XC86464AC #XBA5D5DE7 #X3219192B #XE6737395 
       #XC06060A0 #X19818198 #X9E4F4FD1 #XA3DCDC7F 
       #X44222266 #X542A2A7E #X3B9090AB #X0B888883 
       #X8C4646CA #XC7EEEE29 #X6BB8B8D3 #X2814143C 
       #XA7DEDE79 #XBC5E5EE2 #X160B0B1D #XADDBDB76 
       #XDBE0E03B #X64323256 #X743A3A4E #X140A0A1E 
       #X924949DB #X0C06060A #X4824246C #XB85C5CE4 
       #X9FC2C25D #XBDD3D36E #X43ACACEF #XC46262A6 
       #X399191A8 #X319595A4 #XD3E4E437 #XF279798B 
       #XD5E7E732 #X8BC8C843 #X6E373759 #XDA6D6DB7 
       #X018D8D8C #XB1D5D564 #X9C4E4ED2 #X49A9A9E0 
       #XD86C6CB4 #XAC5656FA #XF3F4F407 #XCFEAEA25 
       #XCA6565AF #XF47A7A8E #X47AEAEE9 #X10080818 
       #X6FBABAD5 #XF0787888 #X4A25256F #X5C2E2E72 
       #X381C1C24 #X57A6A6F1 #X73B4B4C7 #X97C6C651 
       #XCBE8E823 #XA1DDDD7C #XE874749C #X3E1F1F21 
       #X964B4BDD #X61BDBDDC #X0D8B8B86 #X0F8A8A85 
       #XE0707090 #X7C3E3E42 #X71B5B5C4 #XCC6666AA 
       #X904848D8 #X06030305 #XF7F6F601 #X1C0E0E12 
       #XC26161A3 #X6A35355F #XAE5757F9 #X69B9B9D0 
       #X17868691 #X99C1C158 #X3A1D1D27 #X279E9EB9 
       #XD9E1E138 #XEBF8F813 #X2B9898B3 #X22111133 
       #XD26969BB #XA9D9D970 #X078E8E89 #X339494A7 
       #X2D9B9BB6 #X3C1E1E22 #X15878792 #XC9E9E920 
       #X87CECE49 #XAA5555FF #X50282878 #XA5DFDF7A 
       #X038C8C8F #X59A1A1F8 #X09898980 #X1A0D0D17 
       #X65BFBFDA #XD7E6E631 #X844242C6 #XD06868B8 
       #X824141C3 #X299999B0 #X5A2D2D77 #X1E0F0F11 
       #X7BB0B0CB #XA85454FC #X6DBBBBD6 #X2C16163A )))

(define-constant +rt0+
    (make-array
     256 :element-type '(unsigned-byte 32)
     :initial-contents
     '(#X51F4A750 #X7E416553 #X1A17A4C3 #X3A275E96 
       #X3BAB6BCB #X1F9D45F1 #XACFA58AB #X4BE30393 
       #X2030FA55 #XAD766DF6 #X88CC7691 #XF5024C25 
       #X4FE5D7FC #XC52ACBD7 #X26354480 #XB562A38F 
       #XDEB15A49 #X25BA1B67 #X45EA0E98 #X5DFEC0E1 
       #XC32F7502 #X814CF012 #X8D4697A3 #X6BD3F9C6 
       #X038F5FE7 #X15929C95 #XBF6D7AEB #X955259DA 
       #XD4BE832D #X587421D3 #X49E06929 #X8EC9C844 
       #X75C2896A #XF48E7978 #X99583E6B #X27B971DD 
       #XBEE14FB6 #XF088AD17 #XC920AC66 #X7DCE3AB4 
       #X63DF4A18 #XE51A3182 #X97513360 #X62537F45 
       #XB16477E0 #XBB6BAE84 #XFE81A01C #XF9082B94 
       #X70486858 #X8F45FD19 #X94DE6C87 #X527BF8B7 
       #XAB73D323 #X724B02E2 #XE31F8F57 #X6655AB2A 
       #XB2EB2807 #X2FB5C203 #X86C57B9A #XD33708A5 
       #X302887F2 #X23BFA5B2 #X02036ABA #XED16825C 
       #X8ACF1C2B #XA779B492 #XF307F2F0 #X4E69E2A1 
       #X65DAF4CD #X0605BED5 #XD134621F #XC4A6FE8A 
       #X342E539D #XA2F355A0 #X058AE132 #XA4F6EB75 
       #X0B83EC39 #X4060EFAA #X5E719F06 #XBD6E1051 
       #X3E218AF9 #X96DD063D #XDD3E05AE #X4DE6BD46 
       #X91548DB5 #X71C45D05 #X0406D46F #X605015FF 
       #X1998FB24 #XD6BDE997 #X894043CC #X67D99E77 
       #XB0E842BD #X07898B88 #XE7195B38 #X79C8EEDB 
       #XA17C0A47 #X7C420FE9 #XF8841EC9 #X00000000 
       #X09808683 #X322BED48 #X1E1170AC #X6C5A724E 
       #XFD0EFFFB #X0F853856 #X3DAED51E #X362D3927 
       #X0A0FD964 #X685CA621 #X9B5B54D1 #X24362E3A 
       #X0C0A67B1 #X9357E70F #XB4EE96D2 #X1B9B919E 
       #X80C0C54F #X61DC20A2 #X5A774B69 #X1C121A16 
       #XE293BA0A #XC0A02AE5 #X3C22E043 #X121B171D 
       #X0E090D0B #XF28BC7AD #X2DB6A8B9 #X141EA9C8 
       #X57F11985 #XAF75074C #XEE99DDBB #XA37F60FD 
       #XF701269F #X5C72F5BC #X44663BC5 #X5BFB7E34 
       #X8B432976 #XCB23C6DC #XB6EDFC68 #XB8E4F163 
       #XD731DCCA #X42638510 #X13972240 #X84C61120 
       #X854A247D #XD2BB3DF8 #XAEF93211 #XC729A16D 
       #X1D9E2F4B #XDCB230F3 #X0D8652EC #X77C1E3D0 
       #X2BB3166C #XA970B999 #X119448FA #X47E96422 
       #XA8FC8CC4 #XA0F03F1A #X567D2CD8 #X223390EF 
       #X87494EC7 #XD938D1C1 #X8CCAA2FE #X98D40B36 
       #XA6F581CF #XA57ADE28 #XDAB78E26 #X3FADBFA4 
       #X2C3A9DE4 #X5078920D #X6A5FCC9B #X547E4662 
       #XF68D13C2 #X90D8B8E8 #X2E39F75E #X82C3AFF5 
       #X9F5D80BE #X69D0937C #X6FD52DA9 #XCF2512B3 
       #XC8AC993B #X10187DA7 #XE89C636E #XDB3BBB7B 
       #XCD267809 #X6E5918F4 #XEC9AB701 #X834F9AA8 
       #XE6956E65 #XAAFFE67E #X21BCCF08 #XEF15E8E6 
       #XBAE79BD9 #X4A6F36CE #XEA9F09D4 #X29B07CD6 
       #X31A4B2AF #X2A3F2331 #XC6A59430 #X35A266C0 
       #X744EBC37 #XFC82CAA6 #XE090D0B0 #X33A7D815 
       #XF104984A #X41ECDAF7 #X7FCD500E #X1791F62F 
       #X764DD68D #X43EFB04D #XCCAA4D54 #XE49604DF 
       #X9ED1B5E3 #X4C6A881B #XC12C1FB8 #X4665517F 
       #X9D5EEA04 #X018C355D #XFA877473 #XFB0B412E 
       #XB3671D5A #X92DBD252 #XE9105633 #X6DD64713 
       #X9AD7618C #X37A10C7A #X59F8148E #XEB133C89 
       #XCEA927EE #XB761C935 #XE11CE5ED #X7A47B13C 
       #X9CD2DF59 #X55F2733F #X1814CE79 #X73C737BF 
       #X53F7CDEA #X5FFDAA5B #XDF3D6F14 #X7844DB86 
       #XCAAFF381 #XB968C43E #X3824342C #XC2A3405F 
       #X161DC372 #XBCE2250C #X283C498B #XFF0D9541 
       #X39A80171 #X080CB3DE #XD8B4E49C #X6456C190 
       #X7BCB8461 #XD532B670 #X486C5C74 #XD0B85742 )))

(define-constant +round-constant+
    #(#X01 #X02 #X04 #X08 #X10 #X20 #X40 #X80 #X1B #X36))

(define-constant +ft1+
    (map-into (make-array 256 :element-type '(unsigned-byte 32))
	      (rot-byte-r) +ft0+))

(define-constant +ft2+
    (map-into (make-array 256 :element-type '(unsigned-byte 32))
	      (rot-byte-r) +ft1+))

(define-constant +ft3+
    (map-into (make-array 256 :element-type '(unsigned-byte 32))
	      (rot-byte-r) +ft2+))

(define-constant +rt1+
    (map-into (make-array 256 :element-type '(unsigned-byte 32))
	      (rot-byte-r) +rt0+))

(define-constant +rt2+
    (map-into (make-array 256 :element-type '(unsigned-byte 32))
	      (rot-byte-r) +rt1+))

(define-constant +rt3+
    (map-into (make-array 256 :element-type '(unsigned-byte 32))
	      (rot-byte-r) +rt2+))

(defun pack-bytes (b0 b1 b2 b3)
    "Mash the four bytes into an intger"
    (declare (type (unsigned-byte 8) b0 b1 b2 b3))
    (logior b3
	    (ash b2 8)
	    (ash b1 16)
	    (ash b0 24)))

(defun sub-word (word)
  "The sub-word transformation"
  (pack-bytes (aref +fs+ (ldb (byte 8 24) word ))
	      (aref +fs+ (ldb (byte 8 16) word))
	      (aref +fs+ (ldb (byte 8 8) word))
	      (aref +fs+ (ldb (byte 8 0) word ))))

(defun rot-byte-L (word)
  "Byte roation to the left"
  (logxor (ash word -24)
	  (logand #Xffffff00 (ash word 8))))

(defun make-key-buf ()
  "Makes a buffer to hold the key schedule"
  (make-array 128
	      :initial-element 0
	      :element-type '(unsigned-byte 32)))

(defun aes-expand-key (key-mat &key (direction :encrypt-decrypt) (bits (* (length key-mat) 8)))
  "Generates the AES key. Direction is :encrypt-decrypt (default),
:encrypt, or :decrypt. The encryption key expansion is slightly
faster than the others. The key material must be an unsigned-byte
array of length 16,24, or 32 (i.e. 128,192, or 256 bits)"
  (unless (member bits '(128 192 256))
    (error "Invalid key size: ~A" bits))
  (let* ((rounds (case bits (128 10) (192 12) (256 14)))
	 (rcon-len (case bits (128 10) (192 8) (256 7)))
	 (Nk (floor (length key-mat) 4))
	 (fkey (expand-key key-mat (make-key-buf) rcon-len Nk))
	 (rkey (unless (eq direction :encrypt)
		 (apply-inv-mix-columns fkey (make-key-buf) rounds))))
    (make-aes-key :bits bits
		  :rounds rounds
		  :fkey fkey
		  :rkey rkey)))

(defun expand-key (key words rcon-len Nk)
  "Expands encryption key schedule for the provied key material"  
  (declare (type (simple-array (unsigned-byte 32) ) words)
	   (type (simple-array (unsigned-byte) ) key)
	   (type (unsigned-byte 8) rcon-len Nk))
  (dotimes (i Nk)
    (setf (aref words i) (pack-bytes (aref key (* 4 i))
				     (aref key (+ 1 (* 4 i)))
				     (aref key (+ 2 (* 4 i)))				     
				     (aref key (+ 3 (* 4 i))))))
  (dotimes (i rcon-len)
    (dotimes (j Nk)
      (declare (type (unsigned-byte 8) i j))
      (let ((tmp (aref words (1- (+ j (* Nk (1+ i)))))))
	(declare (type (unsigned-byte 32) tmp))
	(if (zerop j)
	    (setf tmp (logxor (sub-word (rot-byte-L tmp))
			      (pack-bytes (aref +round-constant+ i) 0 0 0)))
	    (when (and (> Nk 6)
		       (= j 4))
	      (setf tmp (sub-word tmp))))
	(setf (aref words (+ j (* Nk (1+ i))))
	      (logxor (aref words (- (+ j (* (1+ i) Nk)) Nk)) tmp)))))    
  words)

(defun apply-inv-mix-columns (fkey words rounds)
  "Applies the inv-mix-columns on the forward key to make the
reverse key"
  (declare (type (simple-array (unsigned-byte 32)) fkey words)
	   (type (unsigned-byte 8) rounds))      
  ;; the first and last rounds are exceptions
  (dotimes (j 4)
    (setf (aref words j) (aref fkey (+ (* rounds 4) j))
	  (aref words (+ (* rounds 4) j)) (aref fkey j)))
  (dotimes (i (1- rounds))
    (dotimes (j 4)
      (declare (type (unsigned-byte 8) i j))
      (let ((tmp (aref fkey (+ (* (- rounds (1+ i)) 4) j))))
	(declare (type (unsigned-byte 32) tmp))
	(setf (aref words (+ (* (1+ i) 4) j))
	      (logxor (aref +rt0+ (aref +fs+ (ldb (byte 8 24) tmp)))
		      (aref +rt1+ (aref +fs+ (ldb (byte 8 16) tmp)))
		      (aref +rt2+ (aref +fs+ (ldb (byte 8 8) tmp)))
		      (aref +rt3+ (aref +fs+ (ldb (byte 8 0) tmp))))))))
  words)

(defmacro each (lst &body body)
  "Usefull, unrolled, extended dolist"
  (let* ((vars (mapcar #'car lst))
	 (vals (mapcar #'rest lst))
	 (alst (apply #'mapcar  (cons #'(lambda (&rest vals) 
					  (mapcar #'cons vars vals)) vals))))
    (cons 'progn (mapcan #'(lambda (x) (sublis x `,body)) alst))))
 
(defmacro tref (t0 t1 t2 t3 key x0 x1 x2 x3)
  "Table lookup in the T-tables for the given key and state"
  `(logxor ,key	  
	   (aref ,t0 (ldb (byte 8 24) ,x0))
	   (aref ,t1 (ldb (byte 8 16) ,x1))
	   (aref ,t2 (ldb (byte 8 8)  ,x2))
	   (aref ,t3 (ldb (byte 8 0)  ,x3))))

(defmacro sref (s key x0 x1 x2 x3)
  "Table lookup in the S-tables for the given key and state"  
  `(logxor ,key
	   (pack-bytes (aref ,s (ldb (byte 8 24) ,x0))
		       (aref ,s (ldb (byte 8 16) ,x1))
		       (aref ,s (ldb (byte 8 8)  ,x2))
		       (aref ,s (ldb (byte 8 0)  ,x3)))))

(defmacro f-round (key idx in0 in1 in2 in3 out0 out1 out2 out3)
  "Encryption round with provided state in and out"
  `(setf
    ,out0 (tref +ft0+ +ft1+ +ft2+ +ft3+ (aref ,key ,idx) ,in0 ,in1 ,in2 ,in3)
    ,out1 (tref +ft0+ +ft1+ +ft2+ +ft3+ (aref ,key (+ ,idx 1)) ,in1 ,in2 ,in3 ,in0)
    ,out2 (tref +ft0+ +ft1+ +ft2+ +ft3+ (aref ,key (+ ,idx 2)) ,in2 ,in3 ,in0 ,in1)
    ,out3 (tref +ft0+ +ft1+ +ft2+ +ft3+ (aref ,key (+ ,idx 3)) ,in3 ,in0 ,in1 ,in2)))

(defmacro r-round (key idx in0 in1 in2 in3 out0 out1 out2 out3) 
  "Decryption round with provided state in and out"
  `(setf
    ,out0 (tref +rt0+ +rt1+ +rt2+ +rt3+ (aref ,key ,idx) ,in0 ,in3 ,in2 ,in1)
    ,out1 (tref +rt0+ +rt1+ +rt2+ +rt3+ (aref ,key (+ ,idx 1)) ,in1 ,in0 ,in3 ,in2)
    ,out2 (tref +rt0+ +rt1+ +rt2+ +rt3+ (aref ,key (+ ,idx 2)) ,in2 ,in1 ,in0 ,in3)
    ,out3 (tref +rt0+ +rt1+ +rt2+ +rt3+ (aref ,key (+ ,idx 3)) ,in3 ,in2 ,in1 ,in0)))

(defmacro array->state (a off s0 s1 s2 s3)
  "Reads array to local state"
  `(each ((s ,s0 ,s1 ,s2 ,s3) (i 0 4 8 12))
    (setf s (pack-bytes (aref ,a (+ i 0))
                        (aref ,a (+ i ,off 1))
	                (aref ,a (+ i ,off 2))
	                (aref ,a (+ i ,off 3))))))

(defmacro state->array (a off s0 s1 s2 s3)
  "Writes local state to array"
  `(each ((s ,s0 ,s1 ,s2 ,s3) (i 0 4 8 12))
    (setf (aref ,a (+ ,off i))   (ldb (byte 8 24) s)
          (aref ,a (+ ,off i 1)) (ldb (byte 8 16) s)
          (aref ,a (+ ,off i 2)) (ldb (byte 8 8)  s)
          (aref ,a (+ ,off i 3)) (ldb (byte 8 0)  s))))

(defun aes-encrypt (key in &key
		    (out (make-array 16 :element-type 'unsigned-byte))
		    (start-in 0)
		    (start-out 0))
  "Encrypts 16 unsigned bytes with the AES chipher.
Parameters: <key>       expanded key
            <in>        plaintext
            <out>       returned cryptotext
            <start-in>  offset for input array
            <start-out> offset for output array"
  (let ((rounds (aes-key-rounds key))
	(expanded-key (aes-key-fkey key))
	(off start-in)
	(a0 0) (a1 0) (a2 0) (a3 0) (b0 0) (b1 0) (b2 0) (b3 0) (idx 0))
    (declare (type (simple-array (unsigned-byte) ) in out)
	     (type (simple-array (unsigned-byte 32) (128)) expanded-key)
	     (type (unsigned-byte 8) rounds idx)
	     (type (unsigned-byte 28) off)
	     (type (unsigned-byte 32) a0 a1 a2 a3 b0 b1 b2 b3))
    (array->state in off a0 a1 a2 a3)
    (each ((a a0 a1 a2 a3) (i 0 1 2 3))
      (setf a (logxor (aref expanded-key i) a)))   
    ;; The first R - 1 rounds
    (each ((i 4 12 20 28 36))
      (f-round expanded-key (+ i 0) a0 a1 a2 a3 b0 b1 b2 b3)
      (f-round expanded-key (+ i 4) b0 b1 b2 b3 a0 a1 a2 a3))
    (when (> rounds 10)
      (f-round expanded-key 44 a0 a1 a2 a3 b0 b1 b2 b3)
      (f-round expanded-key 48 b0 b1 b2 b3 a0 a1 a2 a3)
      (when (> rounds 12)
	(f-round expanded-key 52 a0 a1 a2 a3 b0 b1 b2 b3)
	(f-round expanded-key 56 b0 b1 b2 b3 a0 a1 a2 a3)))
    ;; The last round, taken out separately
    (setf
     idx (* 4 rounds)
     a0 (sref +fs+ (aref expanded-key idx) b0 b1 b2 b3)
     a1 (sref +fs+ (aref expanded-key (+ idx 1)) b1 b2 b3 b0)
     a2 (sref +fs+ (aref expanded-key (+ idx 2)) b2 b3 b0 b1)
     a3 (sref +fs+ (aref expanded-key (+ idx 3)) b3 b0 b1 b2))
    (setf off start-out)
    (state->array out off a0 a1 a2 a3)
   out))

(defun aes-decrypt (key in &key
		    (out (make-array 16 :element-type 'unsigned-byte))
		    (start-in 0)
		    (start-out 0))
  "Decrypts 16 unsigned bytes with the AES inverse chipher.
Parameters: <key>       expanded key
            <in>        cryptotext
            <out>       returned plaintext
            <start-in>  offset for input array
            <start-out> offset for output array"  
  (let ((rounds (aes-key-rounds key))
	(expanded-key (aes-key-rkey key))
	(off start-in)
	(a0 0) (a1 0) (a2 0) (a3 0) (b0 0) (b1 0) (b2 0) (b3 0) (idx 0))    
    (declare (type (simple-array (unsigned-byte)) in out)
	     (type (unsigned-byte 8) rounds idx)
	     (type (unsigned-byte 28) off)	     
	     (type (simple-array (unsigned-byte 32) (128)) expanded-key)
	     (type (unsigned-byte 32) a0 a1 a2 a3 b0 b1 b2 b3))    
    (array->state in off a0 a1 a2 a3)
    (each ((a a0 a1 a2 a3) (i 0 1 2 3))
      (setf a (logxor (aref expanded-key i) a))) 
    ;; The first R - 1 rounds
    (each ((i 4 12 20 28 36))
      (r-round expanded-key (+ i 0) a0 a1 a2 a3 b0 b1 b2 b3)
      (r-round expanded-key (+ i 4) b0 b1 b2 b3 a0 a1 a2 a3))
    (when (> rounds 10)
      (r-round expanded-key 44 a0 a1 a2 a3 b0 b1 b2 b3)
      (r-round expanded-key 48 b0 b1 b2 b3 a0 a1 a2 a3)
      (when (> rounds 12)
	(r-round expanded-key 52 a0 a1 a2 a3 b0 b1 b2 b3)
	(r-round expanded-key 56 b0 b1 b2 b3 a0 a1 a2 a3)))
    ;; The last round, taken out separately
    (setf
     idx (* 4 rounds)
     a0 (sref +rs+ (aref expanded-key idx) b0 b3 b2 b1)
     a1 (sref +rs+ (aref expanded-key (+ idx 1)) b1 b0 b3 b2)
     a2 (sref +rs+ (aref expanded-key (+ idx 2)) b2 b1 b0 b3)
     a3 (sref +rs+ (aref expanded-key (+ idx 3)) b3 b2 b1 b0))
    (setf off start-out)
    (state->array out off a0 a1 a2 a3)
    out))






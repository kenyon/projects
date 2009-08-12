;;;; Blowfish encryption in ANSI Common Lisp
;;;
;;;; Licence: LGPL
;;;
;;;; Copyright: Joern Inge Vestgaarden, 2005
;;;             <jivestgarden at gmail.com>
;;;
;;;; $Id: blowfish.lisp,v 1.6 2007/01/29 21:13:38 jornv Exp $
;;;
;;;; Status
;;;    Might work
;;;
;;;; About Blowfish
;;;    Blowfish is a block chiper constructed by Bruce Schneier.
;;;    The block length is 64 bits and the key length is between
;;;    32 and 448 bits.
;;;
;;;; Documentation
;;;    <http://www.schneier.com/blowfish.html>
;;;
;;;; About the program
;;;    This implementation is based on the C-implementation
;;;    by Paul Kocher (with some aditional optimisations, though).
;;;    It is developed with CMU CL and SLIME.
;;;
;;;; TODO
;;;    - test
;;;    - better interfaces (e.g. keywords with offset)
;;;    - error detection
;;;    - find something worth encypting
;;;    - speed up

(defpackage "BLOWFISH"
  (:use "COMMON-LISP")
  (:export "BLOWFISH-ENCRYPT"
	   "BLOWFISH-DECRYPT"
	   "BLOWFISH-EXPAND-KEY"))

(in-package :blowfish)

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

(defstruct blowfish-key
  pi S0 S1 S2 S3)

(define-constant +pi+
  (make-array 18 
     :element-type '(unsigned-byte 32)
     :initial-contents
    '( #X243F6A88 #X85A308D3 #X13198A2E #X03707344
       #XA4093822 #X299F31D0 #X082EFA98 #XEC4E6C89
       #X452821E6 #X38D01377 #XBE5466CF #X34E90C6C
       #XC0AC29B7 #XC97C50DD #X3F84D5B5 #XB5470917
       #X9216D5D9 #X8979FB1B
      )))

(define-constant +s0+
  (make-array 256
     :element-type '(unsigned-byte 32)
     :initial-contents
    '( #XD1310BA6 #X98DFB5AC #X2FFD72DB #XD01ADFB7
       #XB8E1AFED #X6A267E96 #XBA7C9045 #XF12C7F99
       #X24A19947 #XB3916CF7 #X0801F2E2 #X858EFC16
       #X636920D8 #X71574E69 #XA458FEA3 #XF4933D7E
       #X0D95748F #X728EB658 #X718BCD58 #X82154AEE
       #X7B54A41D #XC25A59B5 #X9C30D539 #X2AF26013
       #XC5D1B023 #X286085F0 #XCA417918 #XB8DB38EF
       #X8E79DCB0 #X603A180E #X6C9E0E8B #XB01E8A3E
       #XD71577C1 #XBD314B27 #X78AF2FDA #X55605C60
       #XE65525F3 #XAA55AB94 #X57489862 #X63E81440
       #X55CA396A #X2AAB10B6 #XB4CC5C34 #X1141E8CE
       #XA15486AF #X7C72E993 #XB3EE1411 #X636FBC2A
       #X2BA9C55D #X741831F6 #XCE5C3E16 #X9B87931E
       #XAFD6BA33 #X6C24CF5C #X7A325381 #X28958677
       #X3B8F4898 #X6B4BB9AF #XC4BFE81B #X66282193
       #X61D809CC #XFB21A991 #X487CAC60 #X5DEC8032
       #XEF845D5D #XE98575B1 #XDC262302 #XEB651B88
       #X23893E81 #XD396ACC5 #X0F6D6FF3 #X83F44239
       #X2E0B4482 #XA4842004 #X69C8F04A #X9E1F9B5E
       #X21C66842 #XF6E96C9A #X670C9C61 #XABD388F0
       #X6A51A0D2 #XD8542F68 #X960FA728 #XAB5133A3
       #X6EEF0B6C #X137A3BE4 #XBA3BF050 #X7EFB2A98
       #XA1F1651D #X39AF0176 #X66CA593E #X82430E88
       #X8CEE8619 #X456F9FB4 #X7D84A5C3 #X3B8B5EBE
       #XE06F75D8 #X85C12073 #X401A449F #X56C16AA6
       #X4ED3AA62 #X363F7706 #X1BFEDF72 #X429B023D
       #X37D0D724 #XD00A1248 #XDB0FEAD3 #X49F1C09B
       #X075372C9 #X80991B7B #X25D479D8 #XF6E8DEF7
       #XE3FE501A #XB6794C3B #X976CE0BD #X04C006BA
       #XC1A94FB6 #X409F60C4 #X5E5C9EC2 #X196A2463
       #X68FB6FAF #X3E6C53B5 #X1339B2EB #X3B52EC6F
       #X6DFC511F #X9B30952C #XCC814544 #XAF5EBD09
       #XBEE3D004 #XDE334AFD #X660F2807 #X192E4BB3
       #XC0CBA857 #X45C8740F #XD20B5F39 #XB9D3FBDB
       #X5579C0BD #X1A60320A #XD6A100C6 #X402C7279
       #X679F25FE #XFB1FA3CC #X8EA5E9F8 #XDB3222F8
       #X3C7516DF #XFD616B15 #X2F501EC8 #XAD0552AB
       #X323DB5FA #XFD238760 #X53317B48 #X3E00DF82
       #X9E5C57BB #XCA6F8CA0 #X1A87562E #XDF1769DB
       #XD542A8F6 #X287EFFC3 #XAC6732C6 #X8C4F5573
       #X695B27B0 #XBBCA58C8 #XE1FFA35D #XB8F011A0
       #X10FA3D98 #XFD2183B8 #X4AFCB56C #X2DD1D35B
       #X9A53E479 #XB6F84565 #XD28E49BC #X4BFB9790
       #XE1DDF2DA #XA4CB7E33 #X62FB1341 #XCEE4C6E8
       #XEF20CADA #X36774C01 #XD07E9EFE #X2BF11FB4
       #X95DBDA4D #XAE909198 #XEAAD8E71 #X6B93D5A0
       #XD08ED1D0 #XAFC725E0 #X8E3C5B2F #X8E7594B7
       #X8FF6E2FB #XF2122B64 #X8888B812 #X900DF01C
       #X4FAD5EA0 #X688FC31C #XD1CFF191 #XB3A8C1AD
       #X2F2F2218 #XBE0E1777 #XEA752DFE #X8B021FA1
       #XE5A0CC0F #XB56F74E8 #X18ACF3D6 #XCE89E299
       #XB4A84FE0 #XFD13E0B7 #X7CC43B81 #XD2ADA8D9
       #X165FA266 #X80957705 #X93CC7314 #X211A1477
       #XE6AD2065 #X77B5FA86 #XC75442F5 #XFB9D35CF
       #XEBCDAF0C #X7B3E89A0 #XD6411BD3 #XAE1E7E49
       #X00250E2D #X2071B35E #X226800BB #X57B8E0AF
       #X2464369B #XF009B91E #X5563911D #X59DFA6AA
       #X78C14389 #XD95A537F #X207D5BA2 #X02E5B9C5
       #X83260376 #X6295CFA9 #X11C81968 #X4E734A41
       #XB3472DCA #X7B14A94A #X1B510052 #X9A532915
       #XD60F573F #XBC9BC6E4 #X2B60A476 #X81E67400
       #X08BA6FB5 #X571BE91F #XF296EC6B #X2A0DD915
       #XB6636521 #XE7B9F9B6 #XFF34052E #XC5855664
       #X53B02D5D #XA99F8FA1 #X08BA4799 #X6E85076A   
      )))

(define-constant +s1+
  (make-array 256
     :element-type '(unsigned-byte 32)
     :initial-contents
     '(#X4B7A70E9 #XB5B32944 #XDB75092E #XC4192623
       #XAD6EA6B0 #X49A7DF7D #X9CEE60B8 #X8FEDB266
       #XECAA8C71 #X699A17FF #X5664526C #XC2B19EE1
       #X193602A5 #X75094C29 #XA0591340 #XE4183A3E
       #X3F54989A #X5B429D65 #X6B8FE4D6 #X99F73FD6
       #XA1D29C07 #XEFE830F5 #X4D2D38E6 #XF0255DC1
       #X4CDD2086 #X8470EB26 #X6382E9C6 #X021ECC5E
       #X09686B3F #X3EBAEFC9 #X3C971814 #X6B6A70A1
       #X687F3584 #X52A0E286 #XB79C5305 #XAA500737
       #X3E07841C #X7FDEAE5C #X8E7D44EC #X5716F2B8
       #XB03ADA37 #XF0500C0D #XF01C1F04 #X0200B3FF
       #XAE0CF51A #X3CB574B2 #X25837A58 #XDC0921BD
       #XD19113F9 #X7CA92FF6 #X94324773 #X22F54701
       #X3AE5E581 #X37C2DADC #XC8B57634 #X9AF3DDA7
       #XA9446146 #X0FD0030E #XECC8C73E #XA4751E41
       #XE238CD99 #X3BEA0E2F #X3280BBA1 #X183EB331
       #X4E548B38 #X4F6DB908 #X6F420D03 #XF60A04BF
       #X2CB81290 #X24977C79 #X5679B072 #XBCAF89AF
       #XDE9A771F #XD9930810 #XB38BAE12 #XDCCF3F2E
       #X5512721F #X2E6B7124 #X501ADDE6 #X9F84CD87
       #X7A584718 #X7408DA17 #XBC9F9ABC #XE94B7D8C
       #XEC7AEC3A #XDB851DFA #X63094366 #XC464C3D2
       #XEF1C1847 #X3215D908 #XDD433B37 #X24C2BA16
       #X12A14D43 #X2A65C451 #X50940002 #X133AE4DD
       #X71DFF89E #X10314E55 #X81AC77D6 #X5F11199B
       #X043556F1 #XD7A3C76B #X3C11183B #X5924A509
       #XF28FE6ED #X97F1FBFA #X9EBABF2C #X1E153C6E
       #X86E34570 #XEAE96FB1 #X860E5E0A #X5A3E2AB3
       #X771FE71C #X4E3D06FA #X2965DCB9 #X99E71D0F
       #X803E89D6 #X5266C825 #X2E4CC978 #X9C10B36A
       #XC6150EBA #X94E2EA78 #XA5FC3C53 #X1E0A2DF4
       #XF2F74EA7 #X361D2B3D #X1939260F #X19C27960
       #X5223A708 #XF71312B6 #XEBADFE6E #XEAC31F66
       #XE3BC4595 #XA67BC883 #XB17F37D1 #X018CFF28
       #XC332DDEF #XBE6C5AA5 #X65582185 #X68AB9802
       #XEECEA50F #XDB2F953B #X2AEF7DAD #X5B6E2F84
       #X1521B628 #X29076170 #XECDD4775 #X619F1510
       #X13CCA830 #XEB61BD96 #X0334FE1E #XAA0363CF
       #XB5735C90 #X4C70A239 #XD59E9E0B #XCBAADE14
       #XEECC86BC #X60622CA7 #X9CAB5CAB #XB2F3846E
       #X648B1EAF #X19BDF0CA #XA02369B9 #X655ABB50
       #X40685A32 #X3C2AB4B3 #X319EE9D5 #XC021B8F7
       #X9B540B19 #X875FA099 #X95F7997E #X623D7DA8
       #XF837889A #X97E32D77 #X11ED935F #X16681281
       #X0E358829 #XC7E61FD6 #X96DEDFA1 #X7858BA99
       #X57F584A5 #X1B227263 #X9B83C3FF #X1AC24696
       #XCDB30AEB #X532E3054 #X8FD948E4 #X6DBC3128
       #X58EBF2EF #X34C6FFEA #XFE28ED61 #XEE7C3C73
       #X5D4A14D9 #XE864B7E3 #X42105D14 #X203E13E0
       #X45EEE2B6 #XA3AAABEA #XDB6C4F15 #XFACB4FD0
       #XC742F442 #XEF6ABBB5 #X654F3B1D #X41CD2105
       #XD81E799E #X86854DC7 #XE44B476A #X3D816250
       #XCF62A1F2 #X5B8D2646 #XFC8883A0 #XC1C7B6A3
       #X7F1524C3 #X69CB7492 #X47848A0B #X5692B285
       #X095BBF00 #XAD19489D #X1462B174 #X23820E00
       #X58428D2A #X0C55F5EA #X1DADF43E #X233F7061
       #X3372F092 #X8D937E41 #XD65FECF1 #X6C223BDB
       #X7CDE3759 #XCBEE7460 #X4085F2A7 #XCE77326E
       #XA6078084 #X19F8509E #XE8EFD855 #X61D99735
       #XA969A7AA #XC50C06C2 #X5A04ABFC #X800BCADC
       #X9E447A2E #XC3453484 #XFDD56705 #X0E1E9EC9
       #XDB73DBD3 #X105588CD #X675FDA79 #XE3674340
       #XC5C43465 #X713E38D8 #X3D28F89E #XF16DFF20
       #X153E21E7 #X8FB03D4A #XE6E39F2B #XDB83ADF7   
       )))

(define-constant +s2+
  (make-array 256
     :element-type '(unsigned-byte 32)
     :initial-contents     
     '(#XE93D5A68 #X948140F7 #XF64C261C #X94692934
       #X411520F7 #X7602D4F7 #XBCF46B2E #XD4A20068
       #XD4082471 #X3320F46A #X43B7D4B7 #X500061AF
       #X1E39F62E #X97244546 #X14214F74 #XBF8B8840
       #X4D95FC1D #X96B591AF #X70F4DDD3 #X66A02F45
       #XBFBC09EC #X03BD9785 #X7FAC6DD0 #X31CB8504
       #X96EB27B3 #X55FD3941 #XDA2547E6 #XABCA0A9A
       #X28507825 #X530429F4 #X0A2C86DA #XE9B66DFB
       #X68DC1462 #XD7486900 #X680EC0A4 #X27A18DEE
       #X4F3FFEA2 #XE887AD8C #XB58CE006 #X7AF4D6B6
       #XAACE1E7C #XD3375FEC #XCE78A399 #X406B2A42
       #X20FE9E35 #XD9F385B9 #XEE39D7AB #X3B124E8B
       #X1DC9FAF7 #X4B6D1856 #X26A36631 #XEAE397B2
       #X3A6EFA74 #XDD5B4332 #X6841E7F7 #XCA7820FB
       #XFB0AF54E #XD8FEB397 #X454056AC #XBA489527
       #X55533A3A #X20838D87 #XFE6BA9B7 #XD096954B
       #X55A867BC #XA1159A58 #XCCA92963 #X99E1DB33
       #XA62A4A56 #X3F3125F9 #X5EF47E1C #X9029317C
       #XFDF8E802 #X04272F70 #X80BB155C #X05282CE3
       #X95C11548 #XE4C66D22 #X48C1133F #XC70F86DC
       #X07F9C9EE #X41041F0F #X404779A4 #X5D886E17
       #X325F51EB #XD59BC0D1 #XF2BCC18F #X41113564
       #X257B7834 #X602A9C60 #XDFF8E8A3 #X1F636C1B
       #X0E12B4C2 #X02E1329E #XAF664FD1 #XCAD18115
       #X6B2395E0 #X333E92E1 #X3B240B62 #XEEBEB922
       #X85B2A20E #XE6BA0D99 #XDE720C8C #X2DA2F728
       #XD0127845 #X95B794FD #X647D0862 #XE7CCF5F0
       #X5449A36F #X877D48FA #XC39DFD27 #XF33E8D1E
       #X0A476341 #X992EFF74 #X3A6F6EAB #XF4F8FD37
       #XA812DC60 #XA1EBDDF8 #X991BE14C #XDB6E6B0D
       #XC67B5510 #X6D672C37 #X2765D43B #XDCD0E804
       #XF1290DC7 #XCC00FFA3 #XB5390F92 #X690FED0B
       #X667B9FFB #XCEDB7D9C #XA091CF0B #XD9155EA3
       #XBB132F88 #X515BAD24 #X7B9479BF #X763BD6EB
       #X37392EB3 #XCC115979 #X8026E297 #XF42E312D
       #X6842ADA7 #XC66A2B3B #X12754CCC #X782EF11C
       #X6A124237 #XB79251E7 #X06A1BBE6 #X4BFB6350
       #X1A6B1018 #X11CAEDFA #X3D25BDD8 #XE2E1C3C9
       #X44421659 #X0A121386 #XD90CEC6E #XD5ABEA2A
       #X64AF674E #XDA86A85F #XBEBFE988 #X64E4C3FE
       #X9DBC8057 #XF0F7C086 #X60787BF8 #X6003604D
       #XD1FD8346 #XF6381FB0 #X7745AE04 #XD736FCCC
       #X83426B33 #XF01EAB71 #XB0804187 #X3C005E5F
       #X77A057BE #XBDE8AE24 #X55464299 #XBF582E61
       #X4E58F48F #XF2DDFDA2 #XF474EF38 #X8789BDC2
       #X5366F9C3 #XC8B38E74 #XB475F255 #X46FCD9B9
       #X7AEB2661 #X8B1DDF84 #X846A0E79 #X915F95E2
       #X466E598E #X20B45770 #X8CD55591 #XC902DE4C
       #XB90BACE1 #XBB8205D0 #X11A86248 #X7574A99E
       #XB77F19B6 #XE0A9DC09 #X662D09A1 #XC4324633
       #XE85A1F02 #X09F0BE8C #X4A99A025 #X1D6EFE10
       #X1AB93D1D #X0BA5A4DF #XA186F20F #X2868F169
       #XDCB7DA83 #X573906FE #XA1E2CE9B #X4FCD7F52
       #X50115E01 #XA70683FA #XA002B5C4 #X0DE6D027
       #X9AF88C27 #X773F8641 #XC3604C06 #X61A806B5
       #XF0177A28 #XC0F586E0 #X006058AA #X30DC7D62
       #X11E69ED7 #X2338EA63 #X53C2DD94 #XC2C21634
       #XBBCBEE56 #X90BCB6DE #XEBFC7DA1 #XCE591D76
       #X6F05E409 #X4B7C0188 #X39720A3D #X7C927C24
       #X86E3725F #X724D9DB9 #X1AC15BB4 #XD39EB8FC
       #XED545578 #X08FCA5B5 #XD83D7CD3 #X4DAD0FC4
       #X1E50EF5E #XB161E6F8 #XA28514D9 #X6C51133C
       #X6FD5C7E7 #X56E14EC4 #X362ABFCE #XDDC6C837
       #XD79A3234 #X92638212 #X670EFA8E #X406000E0  
       )))

(define-constant +s3+
  (make-array 256
     :element-type '(unsigned-byte 32)
     :initial-contents       
     '(#X3A39CE37 #XD3FAF5CF #XABC27737 #X5AC52D1B
       #X5CB0679E #X4FA33742 #XD3822740 #X99BC9BBE
       #XD5118E9D #XBF0F7315 #XD62D1C7E #XC700C47B
       #XB78C1B6B #X21A19045 #XB26EB1BE #X6A366EB4
       #X5748AB2F #XBC946E79 #XC6A376D2 #X6549C2C8
       #X530FF8EE #X468DDE7D #XD5730A1D #X4CD04DC6
       #X2939BBDB #XA9BA4650 #XAC9526E8 #XBE5EE304
       #XA1FAD5F0 #X6A2D519A #X63EF8CE2 #X9A86EE22
       #XC089C2B8 #X43242EF6 #XA51E03AA #X9CF2D0A4
       #X83C061BA #X9BE96A4D #X8FE51550 #XBA645BD6
       #X2826A2F9 #XA73A3AE1 #X4BA99586 #XEF5562E9
       #XC72FEFD3 #XF752F7DA #X3F046F69 #X77FA0A59
       #X80E4A915 #X87B08601 #X9B09E6AD #X3B3EE593
       #XE990FD5A #X9E34D797 #X2CF0B7D9 #X022B8B51
       #X96D5AC3A #X017DA67D #XD1CF3ED6 #X7C7D2D28
       #X1F9F25CF #XADF2B89B #X5AD6B472 #X5A88F54C
       #XE029AC71 #XE019A5E6 #X47B0ACFD #XED93FA9B
       #XE8D3C48D #X283B57CC #XF8D56629 #X79132E28
       #X785F0191 #XED756055 #XF7960E44 #XE3D35E8C
       #X15056DD4 #X88F46DBA #X03A16125 #X0564F0BD
       #XC3EB9E15 #X3C9057A2 #X97271AEC #XA93A072A
       #X1B3F6D9B #X1E6321F5 #XF59C66FB #X26DCF319
       #X7533D928 #XB155FDF5 #X03563482 #X8ABA3CBB
       #X28517711 #XC20AD9F8 #XABCC5167 #XCCAD925F
       #X4DE81751 #X3830DC8E #X379D5862 #X9320F991
       #XEA7A90C2 #XFB3E7BCE #X5121CE64 #X774FBE32
       #XA8B6E37E #XC3293D46 #X48DE5369 #X6413E680
       #XA2AE0810 #XDD6DB224 #X69852DFD #X09072166
       #XB39A460A #X6445C0DD #X586CDECF #X1C20C8AE
       #X5BBEF7DD #X1B588D40 #XCCD2017F #X6BB4E3BB
       #XDDA26A7E #X3A59FF45 #X3E350A44 #XBCB4CDD5
       #X72EACEA8 #XFA6484BB #X8D6612AE #XBF3C6F47
       #XD29BE463 #X542F5D9E #XAEC2771B #XF64E6370
       #X740E0D8D #XE75B1357 #XF8721671 #XAF537D5D
       #X4040CB08 #X4EB4E2CC #X34D2466A #X0115AF84
       #XE1B00428 #X95983A1D #X06B89FB4 #XCE6EA048
       #X6F3F3B82 #X3520AB82 #X011A1D4B #X277227F8
       #X611560B1 #XE7933FDC #XBB3A792B #X344525BD
       #XA08839E1 #X51CE794B #X2F32C9B7 #XA01FBAC9
       #XE01CC87E #XBCC7D1F6 #XCF0111C3 #XA1E8AAC7
       #X1A908749 #XD44FBD9A #XD0DADECB #XD50ADA38
       #X0339C32A #XC6913667 #X8DF9317C #XE0B12B4F
       #XF79E59B7 #X43F5BB3A #XF2D519FF #X27D9459C
       #XBF97222C #X15E6FC2A #X0F91FC71 #X9B941525
       #XFAE59361 #XCEB69CEB #XC2A86459 #X12BAA8D1
       #XB6C1075E #XE3056A0C #X10D25065 #XCB03A442
       #XE0EC6E0E #X1698DB3B #X4C98A0BE #X3278E964
       #X9F1F9532 #XE0D392DF #XD3A0342B #X8971F21E
       #X1B0A7441 #X4BA3348C #XC5BE7120 #XC37632D8
       #XDF359F8D #X9B992F2E #XE60B6F47 #X0FE3F11D
       #XE54CDA54 #X1EDAD891 #XCE6279CF #XCD3E7E6F
       #X1618B166 #XFD2C1D05 #X848FD2C5 #XF6FB2299
       #XF523F357 #XA6327623 #X93A83531 #X56CCCD02
       #XACF08162 #X5A75EBB5 #X6E163697 #X88D273CC
       #XDE966292 #X81B949D0 #X4C50901B #X71C65614
       #XE6C6C7BD #X327A140A #X45E1D006 #XC3F27B9A
       #XC9AA53FD #X62A80F00 #XBB25BFE2 #X35BDD2F6
       #X71126905 #XB2040222 #XB6CBCF7C #XCD769C2B
       #X53113EC0 #X1640E3D3 #X38ABBD60 #X2547ADF0
       #XBA38209C #XF746CE76 #X77AFA1C5 #X20756060
       #X85CBFE4E #X8AE88DD8 #X7AAAF9B0 #X4CF9AA7E
       #X1948C25C #X02FB8A8C #X01C36AE4 #XD6EBE1F9
       #X90D4F869 #XA65CDEA0 #X3F09252D #XC208E69F
       #XB74E6132 #XCE77E25B #X578FDFE3 #X3AC372E6  
      )))


(defmacro each (lst &body body)
  "Usefull, unrolled, extended dolist"
  (let* ((vars (mapcar #'car lst))
	 (vals (mapcar #'rest lst))
	 (alst (apply #'mapcar  (cons #'(lambda (&rest vals) (mapcar #'cons vars vals)) vals))))
    (cons 'progn (mapcan #'(lambda (x) (sublis x `,body)) alst))))
 
(defmacro array->state (a off xl xr)
  "Reads array to local state"
  `(each ((s ,xl ,xr) (i 0 4))
    (setf s (logior (ash (aref ,a (+ ,off i))   24)
		    (ash (aref ,a (+ ,off i 1)) 16)
		    (ash (aref ,a (+ ,off i 2)) 8 )
		         (aref ,a (+ ,off i 3)    )))))

(defmacro state->array (a off xl xr)
  "Writes local state to array"
  `(each ((s ,xl ,xr) (i 0 4))
    (setf (aref ,a (+ ,off i))   (ldb (byte 8 24) s)
          (aref ,a (+ ,off i 1)) (ldb (byte 8 16) s)
          (aref ,a (+ ,off i 2)) (ldb (byte 8 8)  s)
          (aref ,a (+ ,off i 3)) (ldb (byte 8 0)  s))))

(defmacro F (S0 S1 S2 S3 x)
  `(ldb (byte 32 0)
	(+ (logxor (ldb (byte 32 0)
			(+ (aref ,S0 (ldb (byte 8 24) ,x))
			   (aref ,S1 (ldb (byte 8 16) ,x))))
		   (aref ,S2 (ldb (byte 8 8) ,x)))
	   (aref ,S3 (ldb (byte 8 0) ,x)))))

(defmacro blowfish-round (i P S0 S1 S2 S3 in1 in2 out1 out2)  
  `(setf ,out1 (logxor ,in1 (aref ,P ,i))
	 ,out2 (logxor (F ,S0 ,S1 ,S2 ,S3 ,out1) ,in2)))
  
(defun blowfish-encrypt (key in &key
			 (out (make-array 8 :element-type '(unsigned-byte 8)))
			 (start-in 0)
			 (start-out 0))
  "Encrypts 8 bytes with the Blowfish chipher.
Parameters: <key>       expanded key
            <in>        plaintext
            <out>       returned cryptotext
            <start-in>  input offset
            <start-out> output offset"
  (let ((xl 2) (xr 2)
	(yl 0) (yr 0)
	(off start-in)
	(P (blowfish-key-Pi key))
	(S0 (blowfish-key-S0 key))
	(S1 (blowfish-key-S1 key))
	(S2 (blowfish-key-S2 key))
	(S3 (blowfish-key-S3 key))
	)
    (declare (type (simple-array (unsigned-byte 8)) in out)
	     (type (unsigned-byte 28) off)
	     (type (unsigned-byte 32) xl xr yl yr)
	     (type (simple-array (unsigned-byte 32) (18)) P)
	     (type (simple-array (unsigned-byte 32) (256)) S0 S1 S2 S3))
    (array->state in off xl xr)
    (each ((i 0 2 4 6 8 10 12 14))
      (blowfish-round i      P S0 S1 S2 S3  xl xr yl yr)
      (blowfish-round (1+ i) P S0 S1 S2 S3  yr yl xr xl))
    (setf yr (logxor xl (aref P 16))
	  yl (logxor xr (aref P 17)))
    (setf off start-out)
    (state->array out off yl yr)
    out))

(defun blowfish-decrypt (key in &key
			 (out (make-array 8 :element-type '(unsigned-byte 8)))
			 (start-in 0)
			 (start-out 0))
  "Decrypts 8 bytes with the Blowfish inverse chipher
Parameters: <key>       expanded key
            <in>        cryptotext
            <out>       returned plaintext
            <start-in>  input offset
            <start-out> output offset"
  (let ((xl 2) (xr 2)
	(yl 0) (yr 0)
	(off start-in)
	(P (blowfish-key-Pi key))
	(S0 (blowfish-key-S0 key))
	(S1 (blowfish-key-S1 key))
	(S2 (blowfish-key-S2 key))
	(S3 (blowfish-key-S3 key)))
    (declare (type (simple-array (unsigned-byte 8)) in out)
	     (type (unsigned-byte 28) off)
	     (type (unsigned-byte 32) xl xr yl yr)
	     (type (simple-array (unsigned-byte 32) (18)) P)
	     (type (simple-array (unsigned-byte 32) (256)) S0 S1 S2 S3))
    (array->state in off xl xr)
    (each ((i 17 15 13 11 9 7 5 3))
      (blowfish-round i P S0 S1 S2 S3 xl xr yl yr)
      (blowfish-round (1- i) P S0 S1 S2 S3 yr yl xr xl))
    (setf yr (logxor xl (aref P 1))
	  yl (logxor xr (aref P 0)))
    (setf off start-out)
    (state->array out off yl yr)
    out))

(defun blowfish-expand-key (key)
  "Expands the key-material to a Blowfish key."
  (let* ((datal 0)
	 (datar 0)
	 (ctx (make-blowfish-key 
	       :pi (copy-seq +pi+)
	       :s0 (copy-seq +s0+)
	       :s1 (copy-seq +s1+)
	       :s2 (copy-seq +s2+)
	       :s3 (copy-seq +s3+)
	       ))
	 (buf1 (make-array 8 :element-type '(unsigned-byte 8)))
	 (buf2 (make-array 8 :element-type '(unsigned-byte 8)))
	 (P (blowfish-key-Pi ctx))
	 (S0 (blowfish-key-S0 ctx))
	 (S1 (blowfish-key-S1 ctx))
	 (S2 (blowfish-key-S2 ctx))
	 (S3 (blowfish-key-S3 ctx)))
    (let ((j 0))
      (dotimes (i 18)
	(let ((data 0))
	  (dotimes (k 4)
	    (setf data (logior (ash data 8)
			       (aref key j))
		  j (+ j 1))
	    (when (>= j (length key))
	      (setf j 0)))
	  (setf (aref P i)
		(logxor (aref P i) data)))))
    (dotimes (i 9)
      (state->array buf1 0 datal datar)
      (blowfish-encrypt ctx buf1 :out buf2)
      (array->state buf2 0 datal datar)
      (setf (aref P (* 2 i)) datal
	    (aref P (1+ (* 2 i))) datar))
    (each ((S S0 S1 S2 S3))
      (dotimes (j 128)
	(state->array buf1 0 datal datar)
	(blowfish-encrypt ctx buf1 :out buf2)
	(array->state buf2 0 datal datar)
	(setf (aref S (* 2 j)) datal
	      (aref S (1+ (* 2 j))) datar)))
    ctx))	    



;;;; End of blowfish, beginning of tests stuff



(let ((key (blowfish-expand-key 
	    (make-array 8 :element-type '(unsigned-byte 8)))))
  (defun speed-test ()
    "Test speed"
    (let ((buf (make-array 8 :element-type '(unsigned-byte 8))))
      (dotimes (i 1000000)
	(blowfish-encrypt key buf :out buf)))))

(defun int->array (x a &key (bits 32))
  (let ((len (/ bits 8)))
  (dotimes (i len)
    (setf (aref a i) (ldb (byte 8 (- bits (* i 8) 8)) x)))
  a))
   
(defparameter *test-vectors*
  (mapcar
   #'(lambda (x)
       (mapcar
	#'(lambda (y)
	    (int->array y (make-array 8 :element-type '(unsigned-byte 8)) :bits 64))
	x))
      ;; key             ;; plain text      ;; chipher text
   '((#X0000000000000000 #X0000000000000000 #X4EF997456198DD78)
     (#XFFFFFFFFFFFFFFFF #XFFFFFFFFFFFFFFFF #X51866FD5B85ECB8A)
     (#X3000000000000000 #X1000000000000001 #X7D856F9A613063F2)
     (#X1111111111111111 #X1111111111111111 #X2466DD878B963C9D)
     (#X0123456789ABCDEF #X1111111111111111 #X61F9C3802281B096)
     (#X1111111111111111 #X0123456789ABCDEF #X7D0CC630AFDA1EC7)
     (#X0000000000000000 #X0000000000000000 #X4EF997456198DD78)
     (#XFEDCBA9876543210 #X0123456789ABCDEF #X0ACEAB0FC6A0A28D)
     (#X7CA110454A1A6E57 #X01A1D6D039776742 #X59C68245EB05282B)
     (#X0131D9619DC1376E #X5CD54CA83DEF57DA #XB1B8CC0B250F09A0)
     (#X07A1133E4A0B2686 #X0248D43806F67172 #X1730E5778BEA1DA4)
     (#X3849674C2602319E #X51454B582DDF440A #XA25E7856CF2651EB)
     (#X04B915BA43FEB5B6 #X42FD443059577FA2 #X353882B109CE8F1A)
     (#X0113B970FD34F2CE #X059B5E0851CF143A #X48F4D0884C379918)
     (#X0170F175468FB5E6 #X0756D8E0774761D2 #X432193B78951FC98)
     (#X43297FAD38E373FE #X762514B829BF486A #X13F04154D69D1AE5)
     (#X07A7137045DA2A16 #X3BDD119049372802 #X2EEDDA93FFD39C79)
     (#X04689104C2FD3B2F #X26955F6835AF609A #XD887E0393C2DA6E3)
     (#X37D06BB516CB7546 #X164D5E404F275232 #X5F99D04F5B163969)
     (#X1F08260D1AC2465E #X6B056E18759F5CCA #X4A057A3B24D3977B)
     (#X584023641ABA6176 #X004BD6EF09176062 #X452031C1E4FADA8E)
     (#X025816164629B007 #X480D39006EE762F2 #X7555AE39F59B87BD)
     (#X49793EBC79B3258F #X437540C8698F3CFA #X53C55F9CB49FC019)
     (#X4FB05E1515AB73A7 #X072D43A077075292 #X7A8E7BFA937E89A3)
     (#X49E95D6D4CA229BF #X02FE55778117F12A #XCF9C5D7A4986ADB5)
     (#X018310DC409B26D6 #X1D9D5C5018F728C2 #XD1ABB290658BC778)
     (#X1C587F1C13924FEF #X305532286D6F295A #X55CB3774D13EF201)
     (#X0101010101010101 #X0123456789ABCDEF #XFA34EC4847B268B2)
     (#X1F1F1F1F0E0E0E0E #X0123456789ABCDEF #XA790795108EA3CAE)
     (#XE0FEE0FEF1FEF1FE #X0123456789ABCDEF #XC39E072D9FAC631D)
     (#X0000000000000000 #XFFFFFFFFFFFFFFFF #X014933E0CDAFF6E4)
     (#XFFFFFFFFFFFFFFFF #X0000000000000000 #XF21E9A77B71C49BC)
     (#X0123456789ABCDEF #X0000000000000000 #X245946885754369A)
     (#XFEDCBA9876543210 #XFFFFFFFFFFFFFFFF #X6B5C5A9C5D9E0A5A))))

(defun self-test (&optional (vectors *test-vectors*))
  "Apply blowfish encryption and decryption of test vectors.
Return t if success, nil if fail. Second return value is the
vectors that failed"
  (let ((faults nil))
    (map nil
     #'(lambda (x)
	 (let ((key (blowfish-expand-key (first x)))
	       (buf1 (make-array 8 :element-type '(unsigned-byte 8)))
	       (buf2 (make-array 8 :element-type '(unsigned-byte 8))))
	   (blowfish-encrypt key (second x) :out buf1)
	   (blowfish-decrypt key (third x) :out buf2)
	   (when (or (not (equalp (third x) buf1))
		     (not (equalp (second x) buf2)))
	     (push x faults))))
     vectors)
    (if faults
	(values nil faults)
	(values t nil))))

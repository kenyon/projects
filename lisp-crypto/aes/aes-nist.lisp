;;;; NIST test-stuff for AES
;;;
;;;; Licence: LGPL
;;;
;;;; Copyright: Joern Inge Vestgaarden, 2005
;;;             <jivestgarden at gmail.com>
;;;
;;;; $Id: aes-nist.lisp,v 1.2 2007/01/28 10:40:23 jornv Exp $
;;;
;;;; TODO
;;;    - optimise (no priority)



(defconstant +block-bits+ 128 "Number of  block bits")

(defconstant +block-bytes+ 16)

(defun make-plain-block ()
  "makes a 16 element block"
  (make-array +block-bytes+ :initial-element 0 :element-type 'unsigned-byte))

(defun make-cbc-encrypt (key iv)
  ;; TODO: speed up
  (let ((iv-in (hex-str->bin-array (subseq iv 0 32))))
    #'(lambda (buf &optional (out  (make-plain-block)))
	(map-into iv-in #'logxor iv-in buf)
	(aes-encrypt key iv-in :out out)
	(replace iv-in out)
	out)))

(defun make-cbc-decrypt (key iv)
  ;; TODO: speed up
  (let ((iv-out (hex-str->bin-array (subseq iv 0 32))))
    #'(lambda (buf &optional (out (make-plain-block)))
	(aes-decrypt key buf :out out)
	(map-into out #'logxor out iv-out)
	(replace iv-out buf)	      	     
	out)))

(defun hex-str->bin-array (hex-str)
  "converts a hex string to binary array. Length of
hex string must be mulitple of 2"
  (let* ((bin-len (/ (length hex-str) 2))
	 (bin (make-array bin-len :element-type 'unsigned-byte)))
    (dotimes (i bin-len)
      (setf (aref bin i)
	    (parse-integer hex-str :radix 16
			   :start (* 2 i)
			   :end (* 2 (1+ i)))))   
    bin))

(defun bin-array->hex-str (bin)
  (let ((hex (make-string (* 2 (length bin)))))
    (dotimes (i (length bin))
      (let ((h (format nil "~2,'0X" (aref bin i))))	
	(setf (char hex (* 2 i)) (char h 0))
	(setf (char hex (1+ (* 2 i))) (char h 1))))
    hex))

(defun make-bit-iterator (len)
  (let ((a (make-array (/ len 8)
		       :initial-element 0
		       :element-type 'unsigned-byte))
	(i 0) (j 0))
    #'(lambda ()
	(fill a 0)
	(setf (aref a i) (ash 1 (- 7 j)))
	(incf j)
	(when (= j 8)      
	  (setf j 0)
	  (incf i))
	a)))
   
(defun ecb-vk-kat (out key-size)  
  (let ((pt (make-array 16 :initial-element 0 :element-type 'unsigned-byte))
	(next-key (make-bit-iterator key-size)))
    (format out "~%~%KEYSIZE=~A~%~%" key-size)
    (format out "PT=~A~%~%" (bin-array->hex-str pt))
    (dotimes (i key-size)
      (let* ((key (funcall next-key))
	     (ekey (aes-expand-key key))
	     (ct (aes-encrypt ekey pt))
	     (pt2 (aes-decrypt ekey ct))) 
	(unless (equalp pt pt2)
	  (error "e(d(pt)) != pt"))
	(format out "I=~A~%" (1+ i))
	(format out "KEY=~A~%" (bin-array->hex-str key))
	(format out "CT=~A~%~%" (bin-array->hex-str ct))))
    (format out "==========")))

(defun ecb-vt-kat (out key-size)
  (let ((key (make-array (/ key-size 8)
			 :initial-element 0
			 :element-type 'unsigned-byte))
	(next-text (make-bit-iterator +block-bits+)))
    (format out "~%~%KEYSIZE=~A~%~%" key-size)
    (format out "KEY=~A~%~%" (bin-array->hex-str key))
    (dotimes (i +block-bits+)
      (let* ((pt (funcall next-text))
	     (ekey (aes-expand-key key))
	     (ct (aes-encrypt ekey pt))
	     (pt2 (aes-decrypt ekey ct))) 
	(unless (equalp pt pt2)
	  (error "e(d(pt)) != pt"))
	(format out "I=~A~%" (1+ i))
	(format out "PT=~A~%" (bin-array->hex-str pt))
	(format out "CT=~A~%~%" (bin-array->hex-str ct))))
    (format out "==========")))

(defun ecb-mct (&key
		(stream *standard-output*)
		(direction :encrypt)
		(key "00000000000000000000000000000000")
		(in "00000000000000000000000000000000")
		(num-tests 400))
  (let* ((key-size (* 4 (length key)))
	 (cb (hex-str->bin-array in))
	 (cb-old (make-plain-block)))
    (format stream "=========================~%~%")
    (format stream "KEYSIZE=~A~%~%" key-size)
    (dotimes (i num-tests)
      (format stream "I=~A~%" i)
      (format stream "KEY=~A~%" key)
      (format stream "~A=~A~%"
	      (if (eq direction :encrypt) "PT" "CT")
	      (bin-array->hex-str cb))
      (let ((key (aes-expand-key (hex-str->bin-array key))))
	(if (eql direction :encrypt)
	    (dotimes (j 10000)
	      (replace cb-old cb)
	      (setf cb (aes-encrypt key cb :out cb)))
	  (dotimes (j 10000)
	    (replace cb-old cb)
	    (setf cb (aes-decrypt key cb :out cb)))
	  ))
      (format stream "~A=~A~%~%"
	      (if (eq direction :encrypt) "CT" "PT")
	      (bin-array->hex-str cb))
      (setf key (bin-array->hex-str
		 (map 'vector #'logxor (hex-str->bin-array key)
		      (case key-size
			(128 cb)
			(192 (concatenate 'vector (subseq cb-old 8) cb))
			(256 (concatenate 'vector cb-old cb)))))))))

(defun cbc-mct (&key
		(stream *standard-output*)
		(direction :encrypt)
		(key "00000000000000000000000000000000")
		(in "00000000000000000000000000000000")
		(iv "00000000000000000000000000000000")
		(num-tests 400))
  (let* ((key-size (* 4 (length key)))
	 (in (hex-str->bin-array in))
	 (cb (copy-seq in))
	 (cb-old (make-plain-block)))
    (format stream "=========================~%~%")
    (format stream "KEYSIZE=~A~%~%" key-size)
    (dotimes (i num-tests)
      (format stream "I=~A~%" i)
      (format stream "KEY=~A~%" key)
      (format stream "IV=~A~%" iv)
      (format stream "~A=~A~%"
	      (if (eq direction :encrypt) "PT" "CT")
	      (bin-array->hex-str in))
      (if (eq direction :encrypt)
	  (let ((c (make-cbc-encrypt (aes-expand-key
				      (hex-str->bin-array key)) iv)))
	    (dotimes (j 10000)
	      (replace cb-old cb)
	      (funcall c in cb)
	      (if (= j 0)
		  (setf in (hex-str->bin-array iv))
		(replace in cb-old))))
	(let ((c (make-cbc-decrypt (aes-expand-key
				    (hex-str->bin-array key)) iv)))
	  (dotimes (j 10000)
	    (replace in cb)
	    (funcall c in cb))))
      (format stream "~A=~A~%~%"
	      (if (eq direction :encrypt) "CT" "PT")
	      (bin-array->hex-str cb))      
      (if (eq direction :encrypt)
	  (progn
	    (replace in cb-old)
	    (setf iv (bin-array->hex-str cb)))
	(progn
	  (replace cb-old in)
	  (setf iv (bin-array->hex-str in))
	  (replace in cb)))
      (setf key (bin-array->hex-str
		 (map 'vector #'logxor (hex-str->bin-array key)
		      (case key-size
			(128 cb)
			(192 (concatenate 'vector (subseq cb-old 8) cb))
			(256 (concatenate 'vector cb-old cb)))))))))

(defun make-kats (f filename)
  (with-open-file
   (out filename :direction :output)
   (make-test (format nil "~A (128)" filename) f (list out 128))
   (make-test (format nil "~A (192)" filename) f (list out 192))
   (make-test (format nil "~A (256)" filename) f (list out 256))))

(defun make-vk-kats (&optional (filename "ecb_vk.txt")) 
  (make-kats #'ecb-vk-kat filename))

(defun make-vt-kats (&optional (filename "ecb_vt.txt")) 
  (make-kats #'ecb-vt-kat filename))

(defun make-mcts (f filename)
  (with-open-file
   (out filename :direction :output)
   (make-test (format nil "~A (128)" filename) f
	      (list :stream out :key (make-string 32 :initial-element #\0)))
   (make-test (format nil "~A (192)" filename) f
	      (list :stream out  :key (make-string 48 :initial-element #\0)))
   (make-test  (format nil "~A (256)" filename) f
	      (list :stream out  :key (make-string 64 :initial-element #\0)))
   (format out "===========")))

(defun make-ecb-encrypt-mcts (&optional (filename "ecb_e_m.txt"))
  (make-mcts #'(lambda (&rest args)
		 (apply #'ecb-mct (append '(:direction :encrypt) args)))
	     filename))
					    
(defun make-ecb-decrypt-mcts (&optional (filename "ecb_d_m.txt"))
  (make-mcts #'(lambda (&rest args)
		 (apply #'ecb-mct (append '(:direction :decrypt) args)))
	     filename))

(defun make-cbc-encrypt-mcts (&optional (filename "cbc_e_m.txt"))
  (make-mcts #'(lambda (&rest args)
		 (apply #'cbc-mct (append '(:direction :encrypt) args)))
	     filename))

(defun make-cbc-decrypt-mcts (&optional (filename "cbc_d_m.txt"))
  (make-mcts #'(lambda (&rest args)
		 (apply #'cbc-mct (append '(:direction :decrypt) args)))
	     filename))

(defun make-all-tests ()
  (make-vt-kats)
  (make-vk-kats)
  (make-ecb-encrypt-mcts)
  (make-ecb-decrypt-mcts)
  (make-cbc-encrypt-mcts)
  (make-cbc-decrypt-mcts))

(defun make-test (msg test &optional args)
  (format t "~40A" msg)
  (finish-output)
  (format t "done (~,1Fs)~%" (get-time test args)))

(defun get-time (f &optional args)
  (let ((tm (get-internal-run-time)))
    (apply f args)
    (/ (- (get-internal-run-time) tm)
		  internal-time-units-per-second)))


;; The end


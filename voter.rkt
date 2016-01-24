#lang racket

(require "generic-ssl-connect.rkt")

(provide randint)
(provide getV-No)
(provide cast-vote)
(provide get-candidates)
(provide get-candidates-attr)
(provide get-state)
(provide get-results)
(provide get-voters-abstainers)

;; Maximum random value (to be put in CLA & voter)
(define maxrand 4294967087)

;; Generate random integer from 0 to maxrand.
(define randint
	(λ ()
		(random maxrand)
	)
)

; Gets voting state from CLA
(define (get-state CLAip CLAport cert Kpr CLAcert)
	(define-values (in out) (do-ssl-connection CLAip CLAport cert Kpr CLAcert))
	(write (list "STATE") out)
	(close-output-port out)
	(define response (read in))
	(close-input-port in)
	response
)

; Gets the specified attribute from all candidates
(define (get-candidates-attr attr cands)
	(define pos (- (length (car cands)) (length (member attr (car cands)))))
	(map
		(λ (n)
			(list-ref n pos)
		)
		(cddr cands)
	)
)

;; connect to CLA and get verification number
;; If not authorized, raise exception -6
(define getV-No
	(λ (id CLAip CLAport cert Kpr CLAcert)
		(define-values (in out) (do-ssl-connection CLAip CLAport cert Kpr CLAcert))
		(write (list "GETVNO" id) out)
		(close-output-port out)
		(define newV (read in))
		(close-input-port in)
		(if (number? newV)
			newV
			(raise -6)
		)
	)
)

;; connect to CLA and get voted/non-voted
(define (get-voters-abstainers CLAip CLAport cert Kpr CLAcert)
	(define-values (in out) (do-ssl-connection CLAip CLAport cert Kpr CLAcert))
	(write (list "VOTERS") out)
	(close-output-port out)
	(define response (read in))
	(close-input-port in)
	response
)

;; Test function for testing purposes
(define sendBadCommand
	(λ (ip port command cert Kpr servercert)
		(define-values (in out) (do-ssl-connection ip port cert Kpr servercert))
		(write command out)
		(close-output-port out)
		(define result (read in))
		(close-input-port in)
		(display result)
	)
)

;; connect to CTF and get candidate list
(define (get-candidates CTFip CTFport cert Kpr CTFcert)
	(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
	(write (list "CAND") out)
	(close-output-port out)
	(define response (read in))
	(close-input-port in)
	response
)

;; connect to CTF and send my vote
;; if successful, return nonce generated & write to output file
;; Exceptions:
;; -4: no verification number given yet
;; -5: already voted
;; -6: not authorized
;; -99: bad response from CTF server
(define cast-vote
	(λ (vote V-No CTFip CTFport cert Kpr CTFcert)
		;; check if we've been given a verification number
		(if (< V-No 0)
			(raise -4)
			(let ((nonce (randint)))
				(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
				(write (list "VOTEFOR" vote V-No nonce) out)
				(close-output-port out)
				(define response (read in))
				(close-input-port in)
				(cond
					((equal? response "OK-VOTE")
						nonce
					)
					((equal? response "ALREADY VOTED")
						(raise -5)
					)
					((equal? response "NOT AUTH")
						(raise -6)
					)
					(else
						(raise -99)
					)
				)
			)
		)
	)
)

; connect to CTF and get voting results
(define get-results
	(λ (CTFip CTFport cert Kpr CTFcert)
		(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
		(write (list "RESULTS") out)
		(close-output-port out)
		(define response (read in))
		(close-input-port in)
		response
	)
)

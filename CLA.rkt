#lang racket

(require "generic-server.rkt")
(require "generic-ssl-connect.rkt")

;; Global value storing verification umbers
(define V-No.s '())

;; Global value for state
;; Legal values: "STOP" "RUN" "OVER"
(define state "STOP")

;; Mutex for writing verification numbers
(define V-NoSemaphore (make-semaphore 1))

;; Mutex for state
(define stateSemaphore (make-semaphore 1))

;; Global value for CTF server ip & port
(define usingCTFip "localhost")
(define usingCTFport 11311)

;; Global value storing authorized voters
;; Dummy values for testing purposes
(define authVoters '("abc" "def" "ghi" "jkl" "mno" "pqrs" "tuv" "wxyz"))

;; Maximum random value (to be put in CLA & voter)
(define maxrand 4294967087)

;; Start voting
(define (start-voting CTFip CTFport)
	(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
	(write (list "START") out)
	(close-output-port out)
	(define response (read in))
	(close-input-port in)
	(if (equal? response "OK-START")
		(void)
		(raise -2)
	)
	(set! state "RUN")
)

;; Finish voting
(define (voting-over CTFip CTFport)
	(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
	(write (list "OVER") out)
	(close-output-port out)
	(define response (read in))
	(close-input-port in)
	(if (equal? response "OK-OVER")
		(void)
		(raise -2)
	)
	(set! state "OVER")
)

; Gives only verification numbers
(define (allV-No.s)
	(map car V-No.s)
)

;; Generate random integer from 0 to maxrand. Also checks if number has not
;; been already generated
(define randint
	(λ ()
		(define newV (random maxrand))
		(if (member newV V-No.s)
			(randint)
			newV
		)
	)
)

;; Create a new verification number
;; Voter -> CLA, sends voter identification
;; 	If not authorized, send an error. Otherwise:
;; CLA -> CTF, verification number
;; CLA -> Voter, verification number
;; This function will authorize the voter. If the voter has not been given
;; a verification number a new one will be generated randomly. If the voter
;; has already been given a verification number it will return the same one
;; to the voter.
;; If the given voterID is not an authorized voter the function will raise
;; exception -1
(define authorize!
	(λ (voterID CTFip CTFport voterOut)
		(if (authVoter? voterID)
			(let ((oldV (givenV-No? voterID)))
				(if oldV
					(send-voter oldV voterOut)
					(let ((newV (randint)))
						(send-CTF newV CTFip CTFport)
						(send-voter newV voterOut)
						(set! V-No.s (cons (list newV voterID) V-No.s))
					)
				)
			)
			(raise -1)
		)
	)
)

;; Verifies that the given voter is an authorized voter
(define authVoter?
	(λ (voterID)
		(member voterID authVoters)
	)
)

;; Checks if the voter has already been given a verification number. If true,
;; will return that voter's verification number. If false, will return #f
(define givenV-No?
	(λ (voterID)
		(ormap
			(λ (element)
				(if (equal? (cadr element) voterID)
					(car element)
					#f
				)
			)
			V-No.s
		)
	)
)

;; Sends verification number to CTF
;; If the server doesn't respond "OK" then raise exception -2
(define send-CTF
	(λ (v CTFip CTFport)
		(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
		(write (list "ADDVNO" v) out)
		(close-output-port out)
		(define response (read in))
		(close-input-port in)
		(if (equal? response "OK-VNO")
			(void)
			(raise -2)
		)
	)
)

;; Sends verification number to voter
(define send-voter
	(λ (v voterOut)
		(write v voterOut)
	)
)

(define voters-abstainers
	(λ (CTFip CTFport)
		(define-values (in out) (do-ssl-connection CTFip CTFport cert Kpr CTFcert))
		(write (list "VOTERS") out)
		(close-output-port out)
		(define response (read in))
		; Filter out unused verification numbers
		(define onlyused
			(filter
				(λ(n)
					(member (car n) response)
				)
				V-No.s
			)
		)

		; People who voted
		(define voters (map cadr onlyused))

		; People who abstained
		(define abstainers
			(filter
				(λ(n)
					(not (member n voters))
				)
				authVoters
			)
		)

		(list voters abstainers)
	)
)

;; Handler for giving out verification numbers
(define handle-voter
	(λ (in out)
		;(write (string-append "CLA recieved command: " (read in)) out)
		(define command (read in))
		(with-handlers
			(
				(exn:fail:contract? 
					(λ (err)
						(write "ERR:SYN" out)
					)
				)
				(exn:fail:network:errno?
					(λ (err)
						(write "ERR:NET" out)
					)
				)
				((λ (v) (equal? v -1))
					(λ (err)
						(write "NOT AUTH" out)
					)
				)
				((λ (v) (equal? v -2))
					(λ (err)
						(write "CTF NOT WORKING" out)
					)
				)
			)
			(cond
				((equal? (car command) "STATE")
					(write state out)
				)
				((equal? state "STOP")
					(write "NOT STARTED" out)
				)
				((equal? (car command) "VOTERS")
					(if (not (equal? state "OVER"))
						(write "NOT OVER YET" out)
						(write (voters-abstainers usingCTFip usingCTFport) out)
					)
				)
				((equal? state "OVER")
					(write "VOTING OVER" out)
				)
				((equal? (car command) "GETVNO")
					(let ((voterID (cadr command)))
						(call-with-semaphore V-NoSemaphore (λ() (authorize! voterID usingCTFip usingCTFport out)))
					)
				)
				(else
					(write "ERR:CMD" out)
				)
			)
		)
	)
)

;; Start the servers
;; Ports used:
;; CLA->CTF: 11311
;; Voter->CTF: 12345 (not used here, this is the CLA)
;; Voter->CLA: 11679

(define voterPort 11679)

; SSL stuff
(define cert "certs/CLA.crt")
(define Kpr "certs/CLA.key")
(define CTFcert '("certs/CTF.crt"))
(define votercert '("certs/voter.crt"))

(define stop-voter-server (server handle-voter voterPort cert Kpr votercert))

; Restricted commandline stuff
(define prompt "CLA]")
(define commands '(
	("state" "Current state (STOP | RUN | OVER)" (begin (display state) (display "\n")))
	("start-voting" "Start CTF & CLA voting" (start-voting usingCTFip usingCTFport))
	("finish-voting" "Finish CTF & CLA voting" (voting-over usingCTFip usingCTFport))
	("verif-nums" "Show all verification numbers given" (begin (display V-No.s) (display "\n")))
	("help" "Commands summary" (disp-help commands))
	("quit" "Terminate execution" (exit))
))

(get-commands prompt commands "CLA.rkt")

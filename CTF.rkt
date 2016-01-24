#lang racket

(require "generic-server.rkt")

;; Global value storing verification numbers
(define V-No.s '())

;; Global value for state
;; Legal values: "STOP" "RUN" "OVER"
(define state "STOP")

;; Mutex for writing verification numbers
(define V-NoSemaphore (make-semaphore 1))

;; Mutex for casting votes
(define VotesSemaphore (make-semaphore 1))

;; Mutex for state
(define stateSemaphore (make-semaphore 1))

;; Start voting
(define (start-voting)
	(set! state "RUN")
)

;; Finish voting
(define (voting-over)
	(set! state "OVER")
)

;; Read candidate descriptions read from an external file
(define (all-candidates infile)
	(define in (open-input-file infile))
	(define result (read in))
	(close-input-port in)
	result
)
;; Returns all used verification numbers
(define usedV-No.s
	(λ ()
		(flatten
			(map (λ (l) (map car l))
				(remove* (list '()) (vector->list results))
			)
		)
	)
)

;; Returns all verification numbers, both used and unused, in sorted
;; ascending order
(define allV-No.s
	(λ ()
		(sort (append V-No.s (usedV-No.s)) < )
	)
)

;; Add number to verification number list. If the number already exists
;; it won't be added again, but the function call will still succeed.
(define addV-No!
	(λ (v)
		(if (not (null? (member v V-No.s)))
			(set! V-No.s (cons v V-No.s))
			(set! V-No.s V-No.s)
		)
	)
)

;; Removes from active verification list. If the number isn't active, then the
;; function will raise exception value -1.
(define delV-No!
	(λ (v)
		(if (member v V-No.s)
			(set! V-No.s (remove v V-No.s))
			(raise -1)
		)
	)
)

;; Casts a vote for the specified candidate, with given verification number
;; and nonce. Removes the verification number from the active list, and
;; adds the nonce and used verification number to the candidate list.
;; If the verification number is invalid it raises exception -1
;; If the verification number has already been used it raises exception -2
(define cast-vote
	(λ (cand v nonce)
		(cond
			((member v V-No.s)
				(values
					(vector-set! results cand (cons (list v nonce) (vector-ref results cand)))
					(delV-No! v)
				)
			)
			((member v (usedV-No.s))
				(raise -2)
			)
			(else
				(raise -1)
			)
		)
	)
)

;; Counts how many votes each candidate recieved
(define count-votes
	(λ ()
		(map length (vector->list results))
	)
)

;; Gives nonces for every candidate
(define vote-nonces
	(λ ()
		(map
			(λ (l)
				(if (null? l)
					'()
					(map cadr l)
				)
			)
			(vector->list results)
		)
	)
)

;; Handler for getting new verification numbers from CLA
(define handle-CLA
	(λ (in out)
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
				((equal? (car command) "START")
					(call-with-semaphore stateSemaphore (λ() (start-voting)))
					(write "OK-START" out)
				)
				((equal? (car command) "OVER")
					(call-with-semaphore stateSemaphore (λ() (voting-over)))
					(write "OK-OVER" out)
				)
				((equal? state "STOP")
					(write "NOT STARTED" out)
				)
				((equal? (car command) "VOTERS")
					(if (not (equal? state "OVER"))
						(write "NOT OVER YET" out)
						(write (usedV-No.s) out)
					)
				)
				((equal? state "OVER")
					(write "VOTING OVER" out)
				)
				((equal? (car command) "ADDVNO")
					(let ((newV-No (cadr command)))
						(call-with-semaphore V-NoSemaphore (λ() (addV-No! newV-No)))
						(write "OK-VNO" out)
					)
				)
				(else
					(write "ERR:CMD" out)
				)
			)
		)
	)
)

;; Handler for getting commands from voter
(define handle-voter
	(λ (in out)
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
						(write "ALREADY VOTED" out)
					)
				)
			)
			(cond
				((equal? state "STOP")
					(write "NOT STARTED" out)
				)
				((equal? (car command) "RESULTS")
					(if (equal? state "OVER")
						(write (cons (count-votes) (vote-nonces)) out)
						(write "NOT OVER YET" out)
					)
				)
				((equal? (car command) "CAND")
					(write candidate-desc out)
				)
				((equal? state "OVER")
					(write "VOTING OVER" out)
				)
				((equal? (car command) "VOTEFOR")
					(let (
							(votervote (cadr command))
							(voterV-No (caddr command))
							(voternonce (cadddr command))
						)
						(call-with-semaphore VotesSemaphore (λ() (cast-vote votervote voterV-No voternonce)))
						(write "OK-VOTE" out)
					)
				)
				(else
					(write "ERR:CMD" out)
				)
			)
		)
	)
)

;; Read candidate description file
(define candidate-desc (all-candidates "candidates.txt"))

;; Count the number of candidates
(define num-cand (length (cddr candidate-desc)))

;; Global value storing candidate results
(define results (make-vector num-cand '()))

;; Start the servers
;; Ports used:
;; CLA->CTF: 11311
;; Voter->CTF: 12345
;; Voter->CLA: 11679 (not used here, this is the CTF)

(define CLAport 11311)
(define voterPort 12345)

; SSL stuff
(define cert "certs/CTF.crt")
(define Kpr "certs/CTF.key")
(define verify-certs '("certs/CLA.crt" "certs/voter.crt"))

(define stop-CLA-server (server handle-CLA CLAport cert Kpr verify-certs))
(define stop-voter-server (server handle-voter voterPort cert Kpr verify-certs))

(define (stop-all-servers)
	(stop-CLA-server)
	(stop-voter-server)
)

; Restricted commandline stuff
(define prompt "CTF]")
(define commands '(
	("state" "Current state (STOP | RUN | OVER)" (begin (display state) (display "\n")))
	("results" "Display tabulation" (begin (display (count-votes)) (display "\n")))
	("results-full" "Display tabulation & voter nonces" (begin (display (cons (count-votes) (vote-nonces))) (display "\n")))
	("help" "Commands summary" (disp-help commands))
	("quit" "Terminate execution" (exit))
))

(get-commands prompt commands "CTF.rkt")

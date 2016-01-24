#lang racket

;; Generic server functions used by CLA & CTF

(require openssl)

(provide server)
(provide get-commands)
(provide disp-help)
;(provide do-command)

(define (server handler port servercert serverkey clientcerts)
	(define main-cust (make-custodian))
	(parameterize ([current-custodian main-cust])
		(define server-ctx (ssl-make-server-context))
		(for-each
			(λ(clientcrt)
				(ssl-load-verify-source! server-ctx clientcrt)
			)
			clientcerts
		)
		(define listener (ssl-listen port 5 #t "localhost" server-ctx))
		(ssl-load-private-key! listener serverkey)
		(ssl-load-certificate-chain! listener servercert)
		(ssl-set-verify! listener #t)
		(define loop
			(λ ()
				(accept-and-handle handler listener)
				(loop)
			)
		)
		(thread loop)
	)
	(λ ()
		(custodian-shutdown-all main-cust)
	)
)

(define (accept-and-handle handler listener)
	(define cust (make-custodian))
	(parameterize ([current-custodian cust])
		(define-values (in out) (ssl-accept listener))
		(thread
			(lambda ()
				(handler in out)
				(close-input-port in)
				(close-output-port out)
			)
		)
	)
	; Watcher thread:
	(thread
		(lambda ()
			(sleep 10)
			(custodian-shutdown-all cust)
		)
	)
)

; My own restricted commandline for servers
(define (get-commands prompt commands mod)
	(display prompt)
	; Comment two lines below out if you're running in DrRacket
	;(define readevt (read-line-evt (current-input-port)))
	;(sync readevt)
	(with-handlers
		(
			(exn:break?
			;((λ(v) #t)
				; Forbid breaking out
				(λ (n)
					(display "\n")
					(get-commands prompt commands mod)
				)
			)
		)
		(define cmd (string-downcase (read-line)))
		(if (not (equal? cmd ""))
			(do-command commands cmd mod)
			(void)
		)
		(get-commands prompt commands mod)
	)
)

(define (do-command commands givencmd mod)
	(define ns (module->namespace mod))
	; Pull command from commands list
	(define cmd
		(ormap
			(λ (one-command)
				(if (member givencmd one-command)
					one-command
					#f
				)
			)
			commands
		)
	)
	; Check to see if given cmd is a valid command
	(if cmd
		; True : run the command
		(eval (caddr cmd) ns)
		; False: display error message
		(display "Invalid command. Type \"help\" for commands.\n")
	)
)

(define (disp-help commands)
	(display "Valid commands:\n")
	(for-each
		(λ (one-command)
			(display (car one-command))
			(display "\t")
			(display (cadr one-command))
			(display "\n")
		)
		commands
	)
)

#lang racket/gui

(require "voter.rkt")

(define myID "abc")
(define myV-No -1)
(define myNonce -1)
;(define candidates '())
;; kludges to make set! work
(set! myV-No -1)
(set! myNonce -1)
;(set! candidates '())

;; Ports used:
;; CLA->CTF: 11311 (not used here, this is the voter)
;; Voter->CTF: 12345
;; Voter->CLA: 11679
(define usingCTFip "localhost")
(define usingCTFport 12345)
(define usingCLAip "localhost")
(define usingCLAport 11679)

; SSL stuff
(define cert "certs/voter.crt")
(define Kpr "certs/voter.key")
(define CTFcert '("certs/CTF.crt"))
(define CLAcert '("certs/CLA.crt"))


;; Voting process:
;; 1. Connect to CLA and get verification number
;; 	(set! myV-No (getV-No myID usingCLAip usingCLAport))
;; 2. Connect to CTF and get candidate list
;; 	(get-candidates usingCTFip usingCTFport)
;; 3. Voter chooses candidate
;; 4. Send vote, verification number, nonce to CLA
;; 	(set! myNonce cast-vote vote myV-No usingCTFip usingCTFport)

;; GUI layout:
;; frame: Main window
;; welcomsg: The message at the top
;; choices: Horizontal panel displaying candidate list
;; controls: Horizontal panel with GUI widgets
;; startbutton: Button for interaction
;; cand-choice: Choicebox with candidate choices
;; instrmsg: Instruction messages

; Make a frame by instantiating the frame% class
(define frame
	(new frame%
		[label "Voting"]
		[min-width 620]
		[min-height 500]
	)
)
; Make a static text message in the frame
(define welcomsg
	(new message% [parent frame] 
		[label "Please wait..."]
		[font (make-font #:size 26)]
		[stretchable-width #t]
	)
)
; Panel for displaying candidate choices
(define choices
	(new horizontal-panel%
		[parent frame]
		[style '(auto-hscroll auto-vscroll)]
		[min-height 450]
		[spacing 9]
	)
)

; Panel for controls
(define controls
	(new horizontal-panel%
		[parent frame]
		[alignment '(right center)]
		[min-height 10]
	)
)

; Message for instructions
(define instrmsg
	(new message%
		[parent controls]
		[label "Click the button to begin"]
		[stretchable-width #t]
		[style '(deleted)]
	)
)

; Choicebox for candidate choices
(define cand-choice
	(new choice%
		[parent controls]
		[label "Choose a candidate:"]
		[choices '()]
		[min-width 50]
		[stretchable-width #t]
		[style '(deleted)]
	)
)

; Button to start voting & cast votes
(define startbutton
	(new button%
		[parent controls]
		[label "Start voting"]
		[style '(deleted)]
		; Callback procedure for a button click:
		[callback
			(λ (button event) 
				(cond
					; First step of voting: connect to servers & get data
					((< myV-No 0)
						(send welcomsg set-label "Getting verification number...")
						(with-handlers
							(
								(exn:fail:network?
									(λ (err)
										(send welcomsg set-label "Error connecting to CTF server.")
									)
								)
								; Voter is not authorized
								((λ(v) (equal? v -6))
									(λ (err)
										(send welcomsg set-label "Error: You are not authorized to vote")
										(send frame delete-child controls)
										(send frame delete-child choices)
									)
								)
							)
							(set! myV-No (getV-No myID usingCLAip usingCLAport cert Kpr CLAcert))
							;; connect to CTF, get candidates and set up list
							(with-handlers
								(
									(exn:fail:network?
										(λ (err)
											(send welcomsg set-label "Error connecting to CLA server.")
											; It's ok to reset the verification number since the CTF
											; stores which verification number I've been given
											(set! myV-No -1)
										)
									)
								)
								(define candidates (get-candidates usingCTFip usingCTFport cert Kpr CTFcert))
								(add-cand-panels candidates)
								(send welcomsg set-label "Select a candidate")

								; Add candidate choices to choicebox
								(for-each
									(λ (n)
										(send cand-choice append n)
									)
									(get-candidates-attr "Party" candidates)
								)

								; Change some of the controls around
								(send controls add-child cand-choice)
								(send controls delete-child instrmsg)

								; Change the button label
								(send startbutton set-label "Cast vote")

								; Fixup the order of the controls
								(send controls change-children reverse)
							)
						)
					)
					; Second step of voting: Cast my vote
					((< myNonce 0)
						; Get the selected candidate
						(define vote (send cand-choice get-selection))

						(with-handlers
							(
								(exn:fail:network?
									(λ (err)
										(send welcomsg set-label "Error connecting to CLA server.")
									)
								)
								; Voter has already voted
								((λ(v) (equal? v -5))
									(λ (err)
										(send welcomsg set-label "Error: You have already voted")
										(send frame delete-child controls)
										(send frame delete-child choices)
									)
								)
								; Voter is not authorized
								((λ(v) (equal? v -6))
									(λ (err)
										(send welcomsg set-label "Error: You are not authorized to vote")
										(send frame delete-child controls)
										(send frame delete-child choices)
									)
								)
								; Some other error happened
								((λ(v) (equal? v -99))
									(λ (err)
										(send welcomsg set-label "Error: CTF sent an invalid response")
										(send frame delete-child controls)
										(send frame delete-child choices)
									)
								)
							)

							;; connect to CTF & cast my vote
							(set! myNonce (cast-vote vote myV-No usingCTFip usingCTFport cert Kpr CTFcert))

							; Show result on GUI
							; Thank you message
							(send welcomsg set-label "Thank you for voting.")

							; Show your vote
							(define choices-children (send choices get-children))
							(define voted-candidate (list-ref choices-children vote))
							(map
								(λ (child)
									(send choices delete-child child)
								)
								(remove voted-candidate choices-children)
							)

							; Remove controls
							(send controls delete-child cand-choice)
							(send controls delete-child startbutton)

							; Display nonce
							(send instrmsg set-label (string-append "Your vote number is: " (~a myNonce)))
							(send controls add-child instrmsg)

							; Write vote to output file
							(define outfile (open-output-file "votes.txt" #:exists 'append))
							(write (list myID myNonce vote) outfile)
							(display "\n" outfile)
							(close-output-port outfile)
						)
					)
				)
			)
		]
	)
)

; Button to retry when error happens
(define try-again-button
	(new button%
		[parent controls]
		[label "Retry"]
		[style '(deleted)]
		; Callback procedure for a button click:
		[callback
			(λ (button event) 
				(get-state-GUI)
			)
		]
	)
)

; Function to remove a child
; If the child exists, it will be removed
; If the child doesn't exist, nothing will happen
(define (remove-a-child child parent)
	(let ( (children (send parent get-children)))
		(if (member child children)
			(send parent delete-child child)
			(void)
		)
	)
)

; Function to add a child
; If the child doesn't exist, it will be added
; If the child exists, nothing will happen
(define (add-a-child child parent)
	(let ( (children (send parent get-children)))
		(if (not (member child children))
			(send parent add-child child)
			(void)
		)
	)
)

; Function to add a single candidate panel
(define (one-cand-panel text)
	; A panel holding one candidate
	(define one-cand
		(new vertical-panel%
			[parent choices]
			[alignment '(left top)]
		)
	)
	; add message fields to panel
	(map 
		(λ (n)
			(define newfont
				(cond
					((equal? (cadr n) "H1")
						(make-font #:size 20 #:weight 'bold)
					)
					((equal? (cadr n) "H2")
						(make-font #:size 16)
					)
					(else
						(make-font)
					)
				)
			)
			(new message%
				[label (car n)]
				[parent one-cand]
				[font newfont]
			)
		)
		text
	)
)

; Fill choices panel with candidates
(define (add-cand-panels cand-list)
	; get font attributes
	(define fontattr (cadr cand-list))

	; create text & font attribute pairs
	(define cands&fonts
		(map
			(λ (n)
				(map
					(λ (text font)
						(cons text (list font))
					)
					n fontattr
				)
			)
			(cddr cand-list)
		)
	)

	; create a panel for each candidate
	(for-each one-cand-panel cands&fonts)
)

; Get status from CLA
(define (get-state-GUI)
	(with-handlers
		(
			(exn:fail:network:errno?
				(λ (err)
					(send welcomsg set-label "Error: Could not connect to CLA server")
					(add-a-child try-again-button controls)
				)
			)
		)
		(define currstate (get-state usingCLAip usingCLAport cert Kpr CLAcert))
		(cond
			((equal? currstate "STOP")
				(send welcomsg set-label "Voting has not started yet")
				(add-a-child try-again-button controls)
				;(send controls add-child try-again-button)
			)
			((equal? currstate "RUN")
				(send welcomsg set-label "Welcome to Voting!")
				;(send controls delete-child try-again-button)
				(remove-a-child try-again-button controls)
				(send controls add-child instrmsg)
				(send controls add-child startbutton)
			)
			((equal? currstate "OVER")
				(show-results)
			)
		)
	)
)

; Show the election results
(define (show-results)
	(with-handlers
		(
			(exn:fail:network:errno?
				(λ (err)
					(send welcomsg set-label "Error: Could not connect to CTF server")
					(send controls add-child try-again-button)
				)
			)
		)
		(define results (get-results usingCTFip usingCTFport cert Kpr CTFcert))
		(cond
			((equal? results "NOT OVER YET")
				(send welcomsg set-label "Voting still in progress")
				(send controls add-child try-again-button)
			)
			(else
				(send welcomsg set-label "Results:")
				;(send controls delete-child try-again-button)
				;(send controls delete-child instrmsg)
				;(send controls delete-child startbutton)
				(remove-a-child try-again-button controls)
				(remove-a-child instrmsg controls)
				(remove-a-child startbutton controls)

				(define candidates (get-candidates usingCTFip usingCTFport cert Kpr CTFcert))
				(add-cand-panels candidates)

				; Halve size of candidates panel
				;(send choices min-height (/ (send frame min-height) 2))
				(send choices min-height 60)

				; Show the tally
				(for-each
					(λ (panel tally)
						(new message%
							[label (~a tally)]
							[parent panel]
						)
					)
					(send choices get-children)
					(car results)
				)

				; Show nonces
				(for-each
					(λ (panel nonces)
						(for-each
							(λ (n)
								(new message%
									[label (~a n)]
									[parent panel]
								)
							)
							nonces
						)
					)
					(send choices get-children)
					(cdr results)
				)

				; Show voters/abstainers
				(define voters-abstainers (get-voters-abstainers usingCLAip usingCLAport cert Kpr CLAcert))


				; Panel to show voters/abstainers
				(define va-panel
					(new horizontal-panel%
						[parent frame]
						[style '(auto-vscroll)]
						[alignment '(center top)]
						[min-height 60]
					)
				)

				; Voters
				(define voters-panel
					(new vertical-panel%
						[parent va-panel]
					)
				)
				(new message%
					[label "Voters:"]
					[parent voters-panel]
					[font (make-font #:size 14)]
				)
				(for-each
					(λ(voter)
						(new message%
							[label (~a voter)]
							[parent voters-panel]
						)
					)
					(car voters-abstainers)
				)

				; Abstainers
				(define abstainers-panel
					(new vertical-panel%
						[parent va-panel]
					)
				)
				(new message%
					[label "Abstainers:"]
					[parent abstainers-panel]
					[font (make-font #:size 14)]
				)
				(for-each
					(λ(abstainer)
						(new message%
							[label (~a abstainer)]
							[parent abstainers-panel]
						)
					)
					(cadr voters-abstainers)
				)
			)
		)
	)
)

; Start the GUI running
(send frame show #t)
(get-state-GUI)

#lang racket

(require openssl)

(provide do-ssl-connection)

(define (do-ssl-connection ip port clientcert clientkey server-certs)
	(define client-ctx (ssl-make-client-context))
	(for-each
		(λ(servercrt)
			(ssl-load-verify-source! client-ctx servercrt)
		)
		server-certs
	)
	(ssl-load-certificate-chain! client-ctx clientcert)
	(ssl-load-private-key! client-ctx clientkey)
	(ssl-set-verify! client-ctx #t)
	(ssl-set-verify-hostname! client-ctx #t)
	(ssl-set-ciphers! client-ctx "DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2")
	(ssl-seal-context! client-ctx)
	(ssl-connect ip port client-ctx)
)


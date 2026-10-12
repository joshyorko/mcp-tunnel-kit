.PHONY: setup deploy cas up down status rollback preflight
setup:
	bin/kamal setup-local
deploy:
	bin/kamal accessory deploy
cas:
	bin/kamal accessory deploy cas
up:
	bin/kamal accessory start
down:
	bin/kamal accessory stop
status:
	bin/kamal accessory details
rollback:
	bin/kamal rollback
preflight:
	bin/kamal preflight

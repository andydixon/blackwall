.PHONY: help install migrate bootstrap maintenance status test cs

help:
	@echo "BlackWall OAuth 2.1 + OIDC Server"
	@echo ""
	@echo "Available targets:"
	@echo "  install    - Install dependencies via Composer"
	@echo "  migrate    - Run database migrations"
	@echo "  bootstrap  - Run bootstrap CLI"
	@echo "  maintenance - Run maintenance cleanup jobs"
	@echo "  status     - Show recent maintenance runs"
	@echo "  test       - Run tests"
	@echo "  cs         - Check code style"
	@echo "  health     - Check environment variables"

install:
	composer install

migrate:
	@for f in $$(ls migrations/*.sql | sort); do \
		echo "Applying $$f"; \
		mysql -u$(DB_USER) -p$(DB_PASS) -h$(DB_HOST) $(DB_NAME) < $$f; \
	done

bootstrap:
	php bin/blackwall

maintenance:
	php bin/maintenance cleanup:all

status:
	php bin/maintenance status

test:
	vendor/bin/phpunit

cs:
	vendor/bin/phpcs --standard=PSR12 src/

health:
	@php -r "require 'vendor/autoload.php'; \
		\BlackWall\Config::load('.'); \
		echo 'Checking environment...\n'; \
		\BlackWall\Config::required(['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS', 'APP_URL', 'WEBAUTHN_RP_ID']); \
		echo 'All required vars present!\n';"

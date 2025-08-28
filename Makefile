.PHONY: help install migrate bootstrap test cs

help:
	@echo "BlackWall OAuth 2.1 + OIDC Server"
	@echo ""
	@echo "Available targets:"
	@echo "  install    - Install dependencies via Composer"
	@echo "  migrate    - Run database migrations"
	@echo "  bootstrap  - Run bootstrap CLI"
	@echo "  test       - Run tests"
	@echo "  cs         - Check code style"
	@echo "  health     - Check environment variables"

install:
	composer install

migrate:
	mysql -u$(DB_USER) -p$(DB_PASS) -h$(DB_HOST) $(DB_NAME) < migrations/001_initial_schema.sql

bootstrap:
	php bin/blackwall

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

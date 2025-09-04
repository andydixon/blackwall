<?php

declare(strict_types=1);

namespace BlackWall\Security;

use BlackWall\Database;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Plain;
use PDO;

class JWTManager
{
    private PDO $db;
    private Configuration $config;
    private string $issuer;

    public function __construct()
    {
        $this->db = Database::getInstance();
        $this->issuer = \BlackWall\Config::get('APP_URL');
        $this->ensureSigningKey();
        $this->initializeConfiguration();
    }

    private function ensureSigningKey(): void
    {
        $stmt = $this->db->query('SELECT COUNT(*) FROM jwt_signing_keys WHERE is_active = 1');
        if ((int) $stmt->fetchColumn() === 0) {
            $this->generateSigningKey();
        }
    }

    private function generateSigningKey(): void
    {
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($privateKey, $privateKeyPem);
        $publicKey = openssl_pkey_get_details($privateKey);
        $publicKeyPem = $publicKey['key'];

        $kid = bin2hex(random_bytes(16));

        $stmt = $this->db->prepare(
            'INSERT INTO jwt_signing_keys (kid, private_key, public_key, algorithm, is_active) VALUES (?, ?, ?, ?, 1)'
        );
        $stmt->execute([$kid, $privateKeyPem, $publicKeyPem, 'RS256']);
    }

    private function initializeConfiguration(): void
    {
        $key = $this->getActiveSigningKey();
        
        $this->config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($key['private_key']),
            InMemory::plainText($key['public_key'])
        );
    }

    private function getActiveSigningKey(): array
    {
        $stmt = $this->db->query(
            'SELECT * FROM jwt_signing_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1'
        );
        $key = $stmt->fetch();
        
        if (!$key) {
            throw new \RuntimeException('No active JWT signing key found');
        }

        return $key;
    }

    public function createAccessToken(array $claims): string
    {
        $now = new \DateTimeImmutable();
        $key = $this->getActiveSigningKey();

        $builder = $this->config->builder()
            ->issuedBy($this->issuer)
            ->issuedAt($now)
            ->expiresAt($now->modify('+' . $claims['expires_in'] . ' seconds'))
            ->withHeader('kid', $key['kid'])
            ->relatedTo($claims['sub'])
            ->permittedFor($claims['aud'])
            ->withClaim('scope', $claims['scope'])
            ->withClaim('project_id', $claims['project_id'])
            ->withClaim('privilege_level', $claims['privilege_level'])
            ->withClaim('privilege_name', $claims['privilege_name']);

        if (isset($claims['nonce'])) {
            $builder->withClaim('nonce', $claims['nonce']);
        }

        if (isset($claims['nbf'])) {
            $builder->canOnlyBeUsedAfter($now);
        }

        return $builder->getToken($this->config->signer(), $this->config->signingKey())->toString();
    }

    public function createIdToken(array $claims): string
    {
        $now = new \DateTimeImmutable();
        $key = $this->getActiveSigningKey();

        $builder = $this->config->builder()
            ->issuedBy($this->issuer)
            ->issuedAt($now)
            ->expiresAt($now->modify('+3600 seconds'))
            ->withHeader('kid', $key['kid'])
            ->relatedTo($claims['sub'])
            ->permittedFor($claims['aud']);

        if (isset($claims['nonce'])) {
            $builder->withClaim('nonce', $claims['nonce']);
        }

        if (isset($claims['email'])) {
            $builder->withClaim('email', $claims['email']);
        }

        if (isset($claims['name'])) {
            $builder->withClaim('name', $claims['name']);
        }

        return $builder->getToken($this->config->signer(), $this->config->signingKey())->toString();
    }

    public function getJWKS(): array
    {
        $stmt = $this->db->query('SELECT kid, public_key, algorithm FROM jwt_signing_keys WHERE is_active = 1');
        $keys = [];

        foreach ($stmt->fetchAll() as $row) {
            $publicKey = openssl_pkey_get_details(openssl_pkey_get_public($row['public_key']));
            
            $keys[] = [
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => $row['algorithm'],
                'kid' => $row['kid'],
                'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($publicKey['rsa']['n'])), '='),
                'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($publicKey['rsa']['e'])), '='),
            ];
        }

        return ['keys' => $keys];
    }

    public function parse(string $token): ?Plain
    {
        try {
            return $this->config->parser()->parse($token);
        } catch (\Exception $e) {
            return null;
        }
    }

    public function validate(Plain $token): bool
    {
        $constraints = $this->config->validationConstraints();
        return $this->config->validator()->validate($token, ...$constraints);
    }
}

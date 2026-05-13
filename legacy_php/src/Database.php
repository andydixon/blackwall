<?php

declare(strict_types=1);

namespace BlackWall;

use PDO;

class Database
{
    private static ?PDO $instance = null;

    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            $host = Config::get('DB_HOST');
            $name = Config::get('DB_NAME');
            $user = Config::get('DB_USER');
            $pass = Config::get('DB_PASS');

            $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";
            
            self::$instance = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);

            // Set timezone to UTC
            self::$instance->exec("SET time_zone = '+00:00'");
        }

        return self::$instance;
    }
}

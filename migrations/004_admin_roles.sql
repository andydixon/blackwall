-- Admin RBAC roles for admin panel access control
CREATE TABLE IF NOT EXISTS admin_roles (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    role ENUM('super_admin', 'operator', 'auditor') NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_admin_user (user_id),
    INDEX idx_role_active (role, is_active),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed existing top-level BlackWall admins as super_admin
INSERT INTO admin_roles (user_id, role, is_active)
SELECT DISTINCT upr.user_id, 'super_admin', 1
FROM user_project_roles upr
JOIN projects p ON p.id = upr.project_id
WHERE p.name = 'BlackWall Admin'
  AND upr.privilege_level = 1
ON DUPLICATE KEY UPDATE role = 'super_admin', is_active = 1;

-- --------------------------------------------------------
-- 主机:                           127.0.0.1
-- 服务器版本:                        11.4.2-MariaDB - mariadb.org binary distribution
-- 服务器操作系统:                      Win64
-- HeidiSQL 版本:                  12.6.0.6765
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


-- 导出 zkteco 的数据库结构
CREATE DATABASE IF NOT EXISTS `zkteco` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci */;
USE `zkteco`;

-- 导出  表 zkteco.alembic_version 结构
CREATE TABLE IF NOT EXISTS `alembic_version` (
  `version_num` varchar(32) NOT NULL,
  PRIMARY KEY (`version_num`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.alembic_version 的数据：~0 rows (大约)
DELETE FROM `alembic_version`;

-- 导出  表 zkteco.device 结构
CREATE TABLE IF NOT EXISTS `device` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(100) NOT NULL,
  `alias` varchar(100) NOT NULL,
  `region_id` int(11) DEFAULT NULL,
  `group` varchar(100) DEFAULT NULL,
  `comm_key` int(11) DEFAULT NULL,
  `port` int(11) NOT NULL DEFAULT 4370,
  `code_field_visible` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.device 的数据：~0 rows (大约)
DELETE FROM `device`;

-- 导出  表 zkteco.device_tags 结构
CREATE TABLE IF NOT EXISTS `device_tags` (
  `device_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`device_id`,`tag_id`),
  KEY `tag_id` (`tag_id`),
  CONSTRAINT `device_tags_ibfk_1` FOREIGN KEY (`tag_id`) REFERENCES `tag` (`id`),
  CONSTRAINT `device_tags_ibfk_2` FOREIGN KEY (`device_id`) REFERENCES `device` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.device_tags 的数据：~0 rows (大约)
DELETE FROM `device_tags`;

-- 导出  表 zkteco.log 结构
CREATE TABLE IF NOT EXISTS `log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(150) NOT NULL,
  `timestamp` datetime DEFAULT NULL,
  `username` varchar(150) DEFAULT NULL,
  `ip_address` varchar(100) DEFAULT NULL,
  `user_ip_address` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.log 的数据：~0 rows (大约)
DELETE FROM `log`;
INSERT INTO `log` (`id`, `user_id`, `action`, `timestamp`, `username`, `ip_address`, `user_ip_address`) VALUES
	(1, 1, '用户登录：   管理员', '2024-08-07 19:39:56', 'admin', NULL, '10.117.91.5'),
	(2, 1, '用户修改密码', '2024-08-07 19:40:17', 'admin', NULL, NULL),
	(3, 1, '用户退出登录：', '2024-08-07 19:40:21', 'admin', NULL, '10.117.91.5'),
	(4, 1, '用户登录：   管理员', '2024-08-07 19:40:26', 'admin', NULL, '10.117.91.5');

-- 导出  表 zkteco.region 结构
CREATE TABLE IF NOT EXISTS `region` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.region 的数据：~0 rows (大约)
DELETE FROM `region`;

-- 导出  表 zkteco.tag 结构
CREATE TABLE IF NOT EXISTS `tag` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.tag 的数据：~4 rows (大约)
DELETE FROM `tag`;
INSERT INTO `tag` (`id`, `name`) VALUES
	(2, 'IT办公室'),
	(4, 'IT库房'),
	(1, 'IT机房'),
	(3, 'IT设备间');

-- 导出  表 zkteco.user 结构
CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(150) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `role` varchar(20) NOT NULL,
  `nickname` varchar(255) DEFAULT NULL,
  `allowed_tags` varchar(255) DEFAULT NULL,
  `allowed_groups` varchar(255) DEFAULT NULL,
  `is_disabled` tinyint(1) DEFAULT 0,
  `login_attempts` int(11) DEFAULT 0,
  `last_attempt` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 正在导出表  zkteco.user 的数据：~1 rows (大约)
DELETE FROM `user`;
INSERT INTO `user` (`id`, `username`, `password`, `role`, `nickname`, `allowed_tags`, `allowed_groups`, `is_disabled`, `login_attempts`, `last_attempt`) VALUES
	(1, 'admin', 'scrypt:32768:8:1$Og4yrqNelnLUzOg2$cdace6f1b9f9f9889f2ba03957341a31fc5f5ee33ea2035613b74ed1fe150f5913a046708974130ea71368fdb2fb1f20b632beb80ae0034ca0ca80bc68989302', 'admin', '管理员', NULL, NULL, 0, 0, NULL);

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;

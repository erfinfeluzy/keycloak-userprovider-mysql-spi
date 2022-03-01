CREATE TABLE `users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `firstName` varchar(255) NOT NULL,
  `lastName` varchar(255) NOT NULL,
  `birthDate` date NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;

INSERT INTO `users` (`id`, `username`, `password`, `email`, `firstName`, `lastName`, `birthDate`) VALUES ('1', 'user1', 'sha256(changeme)', 'erfin@example.com', 'erfin', 'feluzy', '2022-02-28'),
('2', 'user2', '057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86', 'erfin2@example.com', 'user2', 'doe', '2022-02-28');

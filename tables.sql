CREATE TABLE User(
  user_id CHAR(36),

  name VARCHAR (32),
  email VARCHAR(80) NOT NULL UNIQUE,
  password CHAR(60),

  join_date DATETIME,
  last_login_date DATETIME,

  PRIMARY KEY (user_id)
);

CREATE TABLE Item (
  item_id INT AUTO_INCREMENT,

  user_id CHAR(36),
  post_date DATETIME,
  body TINYTEXT,

  PRIMARY KEY (item_id),
  FOREIGN KEY (user_id) REFERENCES User (user_id) ON DELETE CASCADE
);
CREATE TABLE user (
    id bigint auto_increment,
    username varchar(200) NOT NULL,
    password varchar(200) NOT NULL,
    authorities varchar(255) NOT NULL,

    PRIMARY KEY (id)
);

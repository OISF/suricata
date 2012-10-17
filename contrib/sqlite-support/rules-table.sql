CREATE TABLE rules (
	sid integer PRIMARY KEY NOT NULL,
	sig text,
	defaction varchar(10),
	defenabled BOOL NOT NULL DEFAULT 0,
	enabled	BOOL NOT NULL DEFAULT 1,
	action varchar(10) NOT NULL,
	classtypes_cid integer
);

CREATE TABLE classtypes (
	cid integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	title varchar(255)
);


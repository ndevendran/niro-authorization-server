create table if not exists APP_USER (
	id identity,
	username varchar(50) not null,
	password varchar(50) not null,
	active boolean not null,
	createdAt timestamp not null
);

create table if not exists AccessToken (
	id identity,
	accessToken varchar(50) not null,
	createdAt timestamp not null
);

create table if not exists AuthorizationRequest (
	id identity,
	createdAt timestamp not null,
	clientId varchar(50) not null,
	clientSecret varchar(50) not null,
	redirectUri varchar(50) not null
);

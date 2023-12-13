create database OnlineBookstore;
use  OnlineBookstore;
create table books(
book_id int primary key,
title varchar(25),
author_id int,
price decimal(5,2), 
publication_year int);

create table authors(
author_id int primary key,
author_name varchar(25),
country varchar(25));

create table orders(
order_id int primary key, 
book_id int,
customer_name varchar(25), 
order_date date);

insert into books values (101,'randamoozham',201,330,2000);
insert into books values(102,'Aadujeevitham',202,450,2003);
insert into books values(103,'Mathilukal',203,550.50,1996);
insert into books values(104,'Chemmeen',204,563,1970);
insert into books values(105,'Nalukettu',201,550,1985);

insert into authors values (201,'MT','India');
insert into authors values (202,'Benyamin','India');
insert into authors values (203,'Basheer','Mexico');
insert into authors values (204,'Thakazhi','Russia');
insert into authors values (205,'Meera','Turkey');

insert into orders values (301,105,'Sruthy','2023-06-23');
insert into orders values (302,101,'Silpa','2023-10-06');
insert into orders values (303,103,'Ranjith','2023-01-13');
insert into orders values (304,102,'Tanay','2023-11-05');
insert into orders values (305,105,'Seetha','2023-02-01');

select title from books;
select author_name from authors;
select * from orders;


alter table books add column genre varchar(20);
alter table orders add column quantity int;

SELECT books.*, authors.author_name, authors.country
FROM books
JOIN authors ON books.author_id = authors.author_id;

SELECT orders.*, books.title, books.price, books.genre
FROM orders
JOIN books ON orders.book_id = books.book_id;

-- 
-- 
--    =========================================
--    Design and Development of Secure Software
--    ============= MSI 2019/2020 =============
--    ======== Practical Assignment #2 ========
--    =========================================
--
--      Department of Informatics Engineering
--              University of Coimbra          
--   
--          Nuno Antunes <nmsa@dei.uc.pt>
--          João Antunes <jcfa@dei.uc.pt>
--          Marco Vieira <mvieira@dei.uc.pt>
-- 
-- 

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS books;

CREATE TABLE users (
    username    VARCHAR( 32)    primary key,
    password    VARCHAR(512)    NOT NULL,
    salt        VARCHAR(512)    NOT NULL,
    otp         VARCHAR(512)
);


CREATE TABLE messages (
    message_id  SERIAL PRIMARY KEY,
    author      VARCHAR( 16)   ,
    message     VARCHAR(256)    NOT NULL
);

CREATE TABLE books (
    book_id         SERIAL PRIMARY KEY,
    title           VARCHAR(128),
    authors         VARCHAR(256),
    category        VARCHAR(128),
    price           NUMERIC(8,2),
    book_date       DATE,
    description     VARCHAR(1024),
    keywords        VARCHAR(256),
    notes           VARCHAR(256),
    recomendation   INTEGER
);


-- Users
insert into users (username, password, salt, otp)
          values ('bcrypt', '$2b$12$4C1YRf3r3zdD07KpPbZw0ue6DDG9EMWVkuk0P0rsGPuc6Vss9Kqnu', '$2b$12$4C1YRf3r3zdD07KpPbZw0u', 'none');

insert into users (username, password, salt, otp)
          values ('teste', 'b123e9e19d217169b981a61188920f9d28638709a5132201684d792b9264271b7f09157ed4321b1c097f7a4abecfc0977d40a7ee599c845883bd1074ca23c4af', 'none', '');

insert into users (username, password, salt, otp)
          values ('rpires', '$2b$12$cnso5RSeALFJnoTYtGEAqutZUSwF2e87UkTCKuuPPb/BYxVBq0IzW', '$2b$12$cnso5RSeALFJnoTYtGEAqu', 'LMO24VLVLNLUHDSIOCPXZYZUWKQGCO6H');

insert into users (username, password, salt, otp)
          values ('dominoro', 'f40df0801e0cbf086287c9f36c1299be4a9378622609b5e5ed54eccebfb5415b7cdaa0baa21264073ade4f7b8d1e99c41e769d2c3359ec5dc5a7edab809a567f', 'f60d28683aaf4467838c16a97252d092', 'none');


insert into users (username, password, salt, otp)
          values ('bcrypt4', '\\x243262243132244d754f667a304c32413234457a75335176684c574d2e2e4b636f6f3364614a54672f59696d38696a4342797571464e773539366643', '\\x243262243132244d754f667a304c32413234457a75335176684c574d2e', 'none');
insert into users (username, password, salt, otp)
          values ('Teste6', '$2b$12$qZiUKuTKldhyuSr6HLWiZuQV5MCZB7ctgzVHIUYISzWQ8f0AmKEzC', '$2b$12$qZiUKuTKldhyuSr6HLWiZu', '62JS2INMLQXUAACF4UREI3JWK7FSE3BF');
insert into users (username, password, salt, otp)
          values ('Teste5', '$2b$12$dh6ZgBYPREvWUfbp7zlScOjz47SeMYaoDVaLaLqaq24zq5ClXbXxC', '$2b$12$dh6ZgBYPREvWUfbp7zlScO', '5NC47TE5VNPWPIRBVXJCTKWFXOYCSSJ5');
insert into users (username, password, salt, otp)
          values ('ruipires', '$2b$12$cnso5RSeALFJnoTYtGEAqutZUSwF2e87UkTCKuuPPb/BYxVBq0IzW', '$2b$12$cnso5RSeALFJnoTYtGEAqu', 'LMO24VLVLNLUHDSIOCPXZYZUWKQGCO6H');

-- Default data for messages
insert into messages (author, message)
          values ('Vulnerable', 'Hi! I wrote this message using Vulnerable Form.');

insert into messages (author, message)
          values ('Correct', 'OMG! This form is so correct!!!');

insert into messages (author, message)
          values ('Vulnerable', 'Oh really?');





-- Default data for books

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Web Database Development : Step by Step', 'Jim Buyens', 'Databases',  39.99, '2007-01-01 12:00:00', 'Web; persistence; sql', 'This is a very nice book.', 10,
            'As Web sites continue to grow in complexity and in the volume of data they must present, databases increasingly drive their content. WEB DATABASE DEVELOPMENT FUNDAMENTALS is ideal for the beginning-to-intermediate Web developer, departmental power user, or entrepreneur who wants to step up to a database-driven Web site-without buying several in-depth guides to the different technologies involved. This book uses the clear Microsoft(r) Step by Step tutorial method to familiarize developers with the technologies for building smart Web sites that present data more easily. ');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Programming Perl (3rd Edition)', 'Larry Wall, Tom Christiansen, Jon Orwant', 'Programming',  39.96, '2009-12-01 12:00:00', 'Perrl; scripts; code', 'This is a very nice book.', 9, 
            'Perl is a powerful programming language that has grown in popularity since it first appeared in 1988. The first edition of this book, Programming Perl, hit the shelves in 1990, and was quickly adopted as the undisputed bible of the language. Since then, Perl has grown with the times, and so has this book.
Programming Perl is not just a book about Perl. It is also a unique introduction to the language and its culture, as you might expect only from its authors. Larry Wall is the inventor of Perl, and provides a unique perspective on the evolution of Perl and its future direction. Tom Christiansen was one of the first champions of the language, and lives and breathes the complexities of Perl internals as few other mortals do. Jon Orwant is the editor of The Perl Journal, which has brought together the Perl community as a common forum for new developments in Perl.');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Perl and CGI for the World Wide Web: Visual QuickStart Guide', 'Elizabeth Castro', 'Programming',  15.19, '2009-06-01 12:00:00', 'Perral; scripts; code', 'This is a very nice book.', 18, 
            'Taking a visual approach, this guide uses ample screen stills to explain the basic components of Perl, and show how to install and customize existing CGI scripts to build interactivity into Web sites.');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Teach Yourself ColdFusion in 21 Days (Teach Yourself -- 21 Days)', 'Charles Mohnike', 'HTML and Web design',  31.99, '2009-06-01 12:00:00', 'Client; scripts; code', 'This is a meager book.', 1, 
            'Sams Teach Yourself ColdFusion in 21 Days quickly empowers you to create your own dynamic database-driven Web applications using Allaire''s ColdFusion. Using client-proven methods, and the success of his popular ColdFusion tutorial for Wired, expert author Charles Mohnike provides you with an understanding of the ColdFusion Server and guides you through the use of the ColdFusion Studio, enabling you to create your own ColdFusion applications quickly and easily. Topics such as installing and configuring the ColdFusion Server, working with the ColdFusion Studio, working with SQL, optimizing your datasource, understanding templates and ColdFusion Markup Language (CFML), using ColdFusion tags, manipulating data, creating e-commerce solutions with ColdFusion, and debugging ColdFusion applications.');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('ColdFusion Fast & Easy Web Development', 'T. C., III Bradley', 'HTML and Web design',  31.99, '2009-06-01 12:00:00', 'Cold; scripts; code', 'This is a meager book.', 1, 
            'Allaires ColdFusion is a powerful solution for developers wanting to build secure, scalable, and manageable Web applications. ColdFusion Fast & Easy Web Development takes a visual approach to learning this Web application server. It combines easy-to-understand instructions and real screen shots for a truly unique learning experience. This book covers topics from ColdFusion basics to retrieving data to building dynamic queries and applications with ColdFusion. The innovative, visual approach of the Fast & Easy Web Development series provides a perfect format for programmers of all levels.');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 1', 'Armando', 'HTML and Web design',  1.99, '2015-06-01 12:00:00', 'galinhas; scripts; caixa', 'Livro de qudradinhos', 1, 
            'quadradinhos 1');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 2', 'Bernardo', 'HTML and Web design',  2.99, '2016-06-01 12:00:00', 'patos; scripts; forte', 'Livro de qudradinhos', 1, 
            'quadradinhos 2');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 3', 'Carlos', 'HTML and Web design',  3.99, '2017-06-01 12:00:00', 'patos; scripts; patagonia', 'Livro de qudradinhos', 1, 
            'quadradinhos 3');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 4', 'David', 'HTML and Web design',  4.99, '2018-06-01 12:00:00', 'patos; scripts; patolandia', 'Livro de qudradinhos', 1, 
            'quadradinhos 4');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 5', 'Eduardo', 'HTML and Web design',  5.99, '2019-06-01 12:00:00', 'patos; scripts; minie', 'Livro de qudradinhos', 1, 
            'quadradinhos 5');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 6', 'Fernando', 'HTML and Web design',  6.99, '2020-06-01 12:00:00', 'patos; scripts; pluto', 'Livro de qudradinhos', 1, 
            'quadradinhos 6');

insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 7', 'George', 'HTML and Web design',  7.99, '2021-06-01 12:00:00', 'patos; scripts; mickey', 'Livro de qudradinhos', 1, 
            'quadradinhos 7');
insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 8', 'Horacio', 'HTML and Web design',  7.99, '2021-12-01 12:00:00', 'patos; scripts; donald', 'Livro de qudradinhos', 1, 
            'quadradinhos 8');
insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 9', 'Jorge', 'HTML and Web design',  7.99, '2021-11-17 12:00:00', 'patos; scripts; huguinho', 'Livro de qudradinhos', 1, 
            'quadradinhos 9');
insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 10', 'Kelvin', 'HTML and Web design',  7.99, '2021-10-01 12:00:00', 'patos; scripts; zezinho', 'Livro de qudradinhos', 1, 
            'quadradinhos 10');
insert into books (title, authors, category, price, book_date, keywords, notes, recomendation,
                   description)
       values('Tio patinhas 11', 'Luisa', 'Databases',  11.99, '2022-01-01 12:00:00', 'patos; scripts; maluquinho', 'Livro de qudradinhos', 1, 
            'quadradinhos 11');

Useful queries - for MySQL and PostgreSQL
=========================================


General Purpose and Useful Queries (MySQL - 99% the same for PostgreSQL) for the files-json.log databases and tables:


::


  mysql>select srcip,http_host,count(*) as total from filejson where magic like "%PDF document%" group by srcip,http_host order by total DESC limit 10;

above top 10 source ip from which PDF's where downloaded
change srcip with dstip to get top 10 IPs downloading PDFs


::


  mysql>select srcip,http_host,count(*) as total from filejson where magic like "%executable%" group by srcip,http_host order by total DESC limit 10;

above top 10 source ip from which executables where downloaded from,
change srcip with dstip to get top 10 IPs downloading executables



::


  mysql> SELECT srcip,http_host,count(*) AS Total , (COUNT(*) / (SELECT COUNT(*) FROM filejson where magic like "%executable%")) * 100 AS 'Percentage to all items'  FROM filejson WHERE magic like "%executable%" GROUP BY srcip,http_host order by total DESC limit 10;

::


  +----------------+----------------------+-------+-------------------------+
  | srcip          | http_host            | Total | Percentage to all items |
  +----------------+----------------------+-------+-------------------------+
  | 149.5.130.7    | ws.livepcsupport.com |   225 |                  9.1167 |
  ..............................
  .............................

This would give you a sorted table  depicting source ip and host name, number of executable downloads from that host/source ip and what  percentage is that of the total executable downloads.
Note: the term executable means  - dll, exe, com, msi, java ... and so on , NOT just .exe files



::


  mysql>select count(magic) as totalPDF from filejson where  magic like "%PDF%"

This will give you the total number of PDFs out of all files


::


  mysql>SELECT ( select count(magic)  from filejson where  magic like "%PDF%" ) as "PDF Total" , (select count(magic) from filejson where  magic like "%executable%") as "Executables Total" , (select count(magic) from filejson where filename like "%.xls") as "Excel Total";

This will give you:

::


  +-----------+-------------------+-------------+
  | PDF Total | Executables Total | Excel Total |
  +-----------+-------------------+-------------+
  |       391 |              2468 |           7 |
  +-----------+-------------------+-------------+


::


  mysql> SELECT ( select count(magic)  from filejson where  magic like "%PDF%" ) as "PDF Total" , (select count(magic) from filejson where  magic like "%executable%") as "Executables Total" , (select count(magic) from filejson where filename like "%.xls") as "Excel Total", (select count(magic) from filejson) as "TOTAL NUMER OF FILES";

::


  +-----------+-------------------+-------------+----------------------+
  | PDF Total | Executables Total | Excel Total | TOTAL NUMER OF FILES |
  +-----------+-------------------+-------------+----------------------+
  |       391 |              2468 |           7 |              3743925 |
  +-----------+-------------------+-------------+----------------------+

the above query - a breakdown for PDF, executables and files hat have extension .xls



::


  mysql>select srcip,filename,http_host,count(*) as total from filejson where filename like "%.xls" group by srcip,filename,http_host order by total DESC limit 10;

the above will select top 10 source ip and document NAMES where excel files (files with extension .xls) were downloaded form


::


  mysql>select srcip,http_host,count(*) as total from filejson where filename like "%.exe" group by srcip,http_host order by total DESC limit 10;

the above will select the top 10 source ips from where ".exe" files where downloaded from


::


  mysql>select srcip,http_host,count(*) as total from filejson where filename like "%.doc" group by srcip,http_host order by total DESC limit 10;

the above for ".doc" files


::


  mysql>select magic,http_host,count(*) as count from filejson group by magic,http_host order by count DESC limit 20;

select top 20 hosts grouped and ordered by count


::


  mysql>select dstip,size,count(*) as total from filejson  group by dstip,size order by total DESC limit 10;

the above query will show you he top 10 downloading ips by size of downloads


::


  mysql>select dstip,http_host,count(*) as total from filejson where filename like "%.exe" group by dstip order by total DESC limit 5;

the above query will show you the top 5 downloading ips (and the hosts they downloaded from) that downloaded files with .exe extensions.


Peter Manev
